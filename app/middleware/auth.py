import os
from dotenv import load_dotenv
from jose import jwt, JWTError, ExpiredSignatureError
from fastapi import Depends, HTTPException, Request
from app.database.connection import SessionLocal
from app.utils.auth import extrair_jti, token_blacklist, adicionar_jti_na_blacklist
from app.database.connection import get_db

load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM  = os.getenv("ALGORITHM")

async def get_current_user(request: Request):
    """Dependency que valida o Bearer token e popula request.state."""
    auth: str | None = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Access token ausente.")

    token = auth.split(" ", 1)[1]
    db = SessionLocal()
    try:
        # decodifica e checa blacklist
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        jti = payload.get("jti")
        if jti and token_blacklist(jti, db):
            raise HTTPException(status_code=401, detail="Access token revogado.")

        # popula estado
        request.state.user_id = payload.get("sub")
        request.state.jti = jti

    except ExpiredSignatureError:
        jti = extrair_jti(token)
        if jti:
            adicionar_jti_na_blacklist(jti, db)
        raise HTTPException(status_code=401, detail="Access token expirado.")
    except JWTError:
        raise HTTPException(status_code=401, detail="Access token inválido.")
    finally:
        db.close()

async def get_current_refresh(
    request: Request,
    db = Depends(get_db),
):
    # Exemplo lendo do header; se for cookie, use request.cookies.get("refresh_token")
    auth: str | None = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(401, "Refresh token ausente.")
    token = auth.split(" ", 1)[1]

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        jti = payload.get("jti")
        if jti and token_blacklist(jti, db):
            raise HTTPException(401, "Refresh token revogado.")
        return payload  # aqui você já pode usar payload["sub"]
    except ExpiredSignatureError:
        raise HTTPException(401, "Refresh token expirado.")
    except JWTError:
        raise HTTPException(401, "Refresh token inválido.")