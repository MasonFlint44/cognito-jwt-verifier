import logging
from typing import Any, Iterable, cast

import aiohttp
import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from jwt import InvalidSignatureError, InvalidTokenError
from jwt.algorithms import RSAAlgorithm

logger = logging.getLogger(__name__)


class AsyncCognitoJwtVerifier:
    def __init__(
        self,
        issuer: str,
        *,
        client_ids: Iterable[str],
        http_timeout: float = 3.0,
        leeway: float = 60.0,
    ) -> None:
        self.issuer = issuer.rstrip("/")
        self.jwks_url = f"{self.issuer}/.well-known/jwks.json"
        self.client_ids = set(client_ids)
        self.leeway = leeway

        # in-memory cache {kid: public_key_object}
        self._keys: dict[str, RSAPublicKey] = {}

        # aiohttp client for non-blocking HTTPS
        timeout = aiohttp.ClientTimeout(total=http_timeout)
        self._session = aiohttp.ClientSession(timeout=timeout)

    async def init_keys(self) -> None:
        """Optional: call at app start to pre-load JWKS."""
        await self._download_jwks()

    async def close(self) -> None:
        """Close the internal aiohttp session (call in shutdown hook)."""
        if not self._session.closed:
            await self._session.close()

    async def _get_key(self, token: str) -> RSAPublicKey:
        """Get the signing key for a given token; downloads JWKS if needed."""
        header = jwt.get_unverified_header(token)
        kid: str | None = header.get("kid")
        if not kid:
            raise InvalidTokenError("Missing 'kid' in token header")

        key = self._keys.get(kid)
        if key is None:
            await self._download_jwks()
            key = self._keys.get(kid)
            if key is None:
                raise InvalidSignatureError(f"Unknown signing key id {kid!r}")
        return key

    async def verify_id_token(self, token: str) -> dict[str, Any]:
        """Verify an ID token; returns claims dict or raises PyJWTError."""
        key = await self._get_key(token)

        claims = jwt.decode(
            jwt=token,
            key=key,
            algorithms=["RS256"],
            issuer=self.issuer,
            audience=self.client_ids,
            leeway=self.leeway,
            options={"require": ["exp", "iat", "iss", "token_use"]},
        )

        # ID token-specific checks
        if claims.get("token_use") != "id":
            raise InvalidTokenError(f"token_use {claims.get('token_use')!r} != id")

        return claims

    async def verify_access_token(self, token: str) -> dict[str, Any]:
        """Verify an access token; returns claims dict or raises PyJWTError."""
        key = await self._get_key(token)

        claims = jwt.decode(
            jwt=token,
            key=key,
            algorithms=["RS256"],
            issuer=self.issuer,
            leeway=self.leeway,
            options={"require": ["exp", "iat", "iss", "token_use"]},
        )

        # Access token-specific checks
        if claims.get("token_use") != "access":
            raise InvalidTokenError(f"token_use {claims.get('token_use')!r} != access")

        client_id = claims.get("client_id")
        if not client_id:
            raise InvalidTokenError("Missing 'client_id' claim in access token")
        if client_id not in self.client_ids:
            raise InvalidTokenError("client_id mismatch")

        return claims

    async def _download_jwks(self) -> None:
        logger.debug("Fetching JWKS from %s", self.jwks_url)
        async with self._session.get(self.jwks_url) as resp:
            resp.raise_for_status()
            jwks = await resp.json()

        new_keys = {
            jwk["kid"]: cast(RSAPublicKey, RSAAlgorithm.from_jwk(jwk))
            for jwk in jwks["keys"]
        }

        if not new_keys:
            raise RuntimeError("JWKS endpoint returned no keys")

        self._keys = new_keys
        logger.debug("JWKS refreshed; %d keys cached", len(self._keys))
