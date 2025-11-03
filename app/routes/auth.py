from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, status, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.models import Pessoa, Usuario
from app.schemas.auth import RegisterIn, RegisterOut, UsuarioOut
from app.dependencies.auth import get_current_user
from app.security.password import hash_password, verify_password, create_access_token

router = APIRouter()

@router.post("/register", response_model=RegisterOut, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterIn, db: Session = Depends(get_db)):
    # validações de unicidade
    if db.scalar(select(Usuario.id).where(Usuario.email == payload.usuario.email)):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="E-mail já cadastrado")
    if payload.pessoa.cpf and db.scalar(select(Pessoa.id).where(Pessoa.cpf == payload.pessoa.cpf)):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="CPF já cadastrado")

    # cria Pessoa e Usuario na mesma transação
    pessoa = Pessoa(
        nome=payload.pessoa.nome,
        cpf=payload.pessoa.cpf,
        data_nascimento=payload.pessoa.data_nascimento,
        telefone=payload.pessoa.telefone,
    )
    db.add(pessoa)
    db.flush()  # garante pessoa.id

    usuario = Usuario(
        pessoa_id=pessoa.id,
        email=payload.usuario.email,
        senha_hash=hash_password(payload.usuario.senha),
    )
    db.add(usuario)
    db.commit()
    db.refresh(pessoa)
    db.refresh(usuario)

    return RegisterOut(pessoa=pessoa, usuario=usuario)

# (Opcional) login simples — mantém id int
from pydantic import BaseModel, EmailStr
class LoginIn(BaseModel):
    email: EmailStr
    senha: str

class MeOut(BaseModel):
    id: int
    pessoa_id: int
    email: EmailStr
    is_active: bool

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

    model_config = {"from_attributes": True}

@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, response: Response, db: Session = Depends(get_db)):
    user = db.execute(select(Usuario).where(Usuario.email == payload.email)).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not verify_password(payload.password, user.senha_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    token = create_access_token(subject=user.id)

    # seta cookie HttpOnly que seu get_current_user já reconhece (session.xaccess)
    response.set_cookie(
        key="session.xaccess",
        value=token,
        httponly=True,
        secure=False,     # True em produção com HTTPS
        samesite="lax",   # ajuste conforme seu frontend
        max_age=60 * 60,  # 1h
        path="/",
    )
    return TokenResponse(access_token=token)

@router.get("/me")
def me(user: Usuario = Depends(get_current_user)):
    # ajuste o shape conforme seu schema/pydantic
    return {
        "id": user.id,
        "email": user.email,
        "pessoa": {
            "id": user.pessoa.id if user.pessoa else None,
            "nome": user.pessoa.nome if user.pessoa else None,
        },
    }

@router.post("/logout")
def logout(response: Response):
    for name in ("session.xaccess", "access_token", "token"):
        response.delete_cookie(key=name, path="/")
    return {"detail": "logged out"}