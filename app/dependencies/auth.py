import os
import jwt
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import select

from app.database.connection import get_db

from app.models.auth import Usuario

SECRET_KEY = os.getenv("SECRET_KEY", "change-me")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
COOKIE_CANDIDATES = ("session.xaccess", "access_token", "token")

def _extract_token(request: Request) -> str | None:
    auth = request.headers.get("authorization") or request.headers.get("Authorization")
    if auth and auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()
    for name in COOKIE_CANDIDATES:
        if name in request.cookies and request.cookies[name]:
            val = request.cookies[name]
            if isinstance(val, str) and val.lower().startswith("bearer "):
                return val.split(" ", 1)[1].strip()
            return val
    return None

def get_current_user(request: Request, db: Session = Depends(get_db)) -> Usuario:
    token = _extract_token(request)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    uid = payload.get("sub") or payload.get("user_id") or payload.get("uid")
    try:
        uid = int(uid)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid subject")

    user = db.execute(
        select(Usuario).options(joinedload(Usuario.pessoa)).where(Usuario.id == uid)
    ).scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    return user
