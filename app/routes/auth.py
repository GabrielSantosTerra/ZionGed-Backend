import re
from fastapi import APIRouter, Depends, HTTPException, status, Response, Request
from sqlalchemy import select, func
from sqlalchemy.orm import Session, joinedload

from pydantic import BaseModel, EmailStr

from app.database.connection import get_db
from app.models import Pessoa, Usuario, TokenBlacklist
from app.schemas.auth import RegisterIn, RegisterOut
from app.security.password import hash_password, verify_password, create_access_token
from app.dependencies.auth import get_current_user, _extract_token, COOKIE_CANDIDATES

router = APIRouter()

@router.post("/register", response_model=RegisterOut, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterIn, db: Session = Depends(get_db)):
    if db.scalar(select(Usuario.id).where(Usuario.email == payload.usuario.email)):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="E-mail já cadastrado")
    if payload.pessoa.cpf and db.scalar(select(Pessoa.id).where(Pessoa.cpf == payload.pessoa.cpf)):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="CPF já cadastrado")

    pessoa = Pessoa(
        nome=payload.pessoa.nome,
        cpf=payload.pessoa.cpf,
        data_nascimento=payload.pessoa.data_nascimento,
        telefone=payload.pessoa.telefone,
    )
    db.add(pessoa)
    db.flush()

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

class LoginInput(BaseModel):
    user: str
    senha: str

@router.post("/login")
def login(payload: LoginInput, response: Response, db: Session = Depends(get_db)):
    u = payload.user.strip()
    if "@" in u:
        q = select(Usuario).options(joinedload(Usuario.pessoa)).where(Usuario.email == u)
    else:
        digits = re.sub(r"\D", "", u)
        if not digits:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Usuário inválido")
        q = (
            select(Usuario)
            .options(joinedload(Usuario.pessoa))
            .join(Pessoa, Usuario.pessoa_id == Pessoa.id)
            .where(func.regexp_replace(Pessoa.cpf, r"[^0-9]", "", "g") == digits)
        )

    user = db.execute(q).scalar_one_or_none()
    if not user or not verify_password(payload.senha, user.senha_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciais inválidas")

    token = create_access_token(user.id)

    response.set_cookie(
        key="session.xaccess",
        value=token,
        httponly=True,
        samesite="lax",
        secure=False,
        path="/",
    )
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "email": user.email,
            "pessoa": {
                "id": user.pessoa.id,
                "nome": user.pessoa.nome,
                "cpf": user.pessoa.cpf
            } if user.pessoa else None,
        },
    }

@router.get("/me")
def me(user: Usuario = Depends(get_current_user)):
    return {
        "id": user.id,
        "email": user.email,
        "pessoa": {
            "id": user.pessoa.id if user.pessoa else None,
            "nome": user.pessoa.nome if user.pessoa else None,
        },
    }

@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    token = _extract_token(request)
    if token:
        db.add(TokenBlacklist(jti=token))
        db.commit()

    for name in COOKIE_CANDIDATES:
        response.delete_cookie(key=name, path="/")

    return {"detail": "logged out"}
