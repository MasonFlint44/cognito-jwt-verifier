# cognito-jwt-verifier

A utility for verifying JWTs issued by AWS Cognito.

## ✨ Features

- **Async & non‑blocking** verification using `aiohttp`.
- Automatic **JWKS caching & key rollover**.
- Validates both **ID** and **access** tokens out‑of‑the‑box.
- Zero heavy dependencies (only `aiohttp`, `PyJWT`, `cryptography`).

## 📦 Installation

```bash
pip install cognito-jwt-verifier
```

## 🚀 Quick Start

```python
import asyncio
from cognito_jwt_verifier import AsyncCognitoJwtVerifier

async def main():
    verifier = AsyncCognitoJwtVerifier(
        issuer="https://cognito-idp.us-east-2.amazonaws.com/<USER_POOL_ID>",
        client_ids=["<APP_CLIENT_ID>"],
    )

    await verifier.init_keys()  # optional warm‑up

    claims = await verifier.verify_id_token("<ID_TOKEN>")
    print(claims)

asyncio.run(main())
```

## 🛡️ FastAPI example

```python
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2AuthorizationCodeBearer
from jwt import PyJWTError

from cognito_jwt_verifier import AsyncCognitoJwtVerifier

ISSUER = "https://cognito-idp.us-east-2.amazonaws.com/us-east-2_ae7uogn5r"
CLIENT_IDS = ["4pvqqexampleclientid"]

verifier = AsyncCognitoJwtVerifier(ISSUER, client_ids=CLIENT_IDS)

oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl=f"{ISSUER}/oauth2/authorize",
    tokenUrl=f"{ISSUER}/oauth2/token",
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    await verifier.init_keys()
    try:
        yield
    finally:
        await verifier.close()

app = FastAPI(lifespan=lifespan)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        return await verifier.verify_access_token(token)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        )

@app.get("/user")
async def read_user(user: dict = Depends(get_current_user)):
    return {"user": user}
```

## 📚 API at a glance

| Method | Description |
|--------|-------------|
| `init_keys()` | Prefetch JWKS (optional). |
| `verify_id_token(token: str)` | Validate an *ID* token & return claims. |
| `verify_access_token(token: str)` | Validate an *access* token & return claims. |
| `close()` | Close the internal `aiohttp` session. |

> If Cognito rotates its keys, the verifier fetches the new JWKS automatically.
