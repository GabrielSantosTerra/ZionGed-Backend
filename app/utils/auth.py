import os
from app.models.blacklist import BlacklistToken
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import jwt, JWTError
from typing import Optional
from uuid import uuid4
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verificar_senha(senha_plana: str, senha_hash: str) -> bool:
    return pwd_context.verify(senha_plana, senha_hash)

def criar_hash_senha(senha: str) -> str:
    return pwd_context.hash(senha)

def criar_access_token(data: dict, expires_delta: timedelta = timedelta(minutes=15)):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire, "jti": str(uuid4())})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verificar_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None

def extrair_jti(token: str) -> str | None:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("jti")
    except JWTError:
        return None

def adicionar_jti_na_blacklist(jti: str, db: Session):
    if jti:
        ja_existe = db.query(BlacklistToken).filter(BlacklistToken.jti == jti).first()
        if not ja_existe:
            db.add(BlacklistToken(jti=jti))
            db.commit()

def token_blacklist(jti: str, db: Session) -> bool:
    return db.query(BlacklistToken).filter_by(jti=jti).first() is not None