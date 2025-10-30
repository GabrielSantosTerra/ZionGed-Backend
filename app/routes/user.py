from datetime import timedelta
from fastapi import APIRouter, HTTPException, Depends, Response, Request
from sqlalchemy.orm import Session
from fastapi.responses import JSONResponse
from app.models.user import Pessoa, Usuario
from app.schemas.user import UserCreateDcto, CadastroResponseDcto, DadosResponseDcto
from passlib.context import CryptContext
from app.database.connection import get_db
from app.utils.auth import verificar_senha, criar_access_token, adicionar_jti_na_blacklist
from app.schemas.user import UserLoginDcto
import os
from dotenv import load_dotenv
from app.middleware.auth import get_current_user, get_current_refresh

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")

router = APIRouter()
protected_router = APIRouter(
    dependencies=[Depends(get_current_user)]
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- Registro de novo usuário + pessoa ---
@router.post(
    "/cadastrar",
    response_model=CadastroResponseDcto,
    status_code=201,
)
def cadastrar(dados: UserCreateDcto, db: Session = Depends(get_db)):
    # Verifica CPF/CNPJ duplicado
    if dados.cpf_cnpj and db.query(Pessoa).filter_by(cpf_cnpj=dados.cpf_cnpj).first():
        return JSONResponse(
            status_code=400,
            content={"mensagem": "CPF/CNPJ já cadastrado."}
        )
    # Cria Pessoa
    pessoa = Pessoa(
        nome=dados.nome,
        cpf_cnpj=dados.cpf_cnpj,
        tipo_pessoa=dados.tipo_pessoa
    )
    db.add(pessoa)
    db.flush()  # garante que pessoa.id exista

    # Cria Usuário
    senha_hash = pwd_context.hash(dados.senha)
    usuario = Usuario(
        id_pessoa=pessoa.id,
        email=dados.email,
        senha=senha_hash
    )
    db.add(usuario)
    db.commit()

    # Carrega do banco para garantir todos os campos
    db.refresh(pessoa)
    db.refresh(usuario)

    response = {"usuario": usuario, "pessoa": pessoa}
    return response

# --- Login ---
@router.post("/entrar")
def entrar(dados: UserLoginDcto, response: Response, db: Session = Depends(get_db)):
    usuario = db.query(Usuario).filter(Usuario.email == dados.email).first()
    if not usuario or not verificar_senha(dados.senha, usuario.senha):
        return JSONResponse(
            status_code=401,
            content={"mensagem": "Email ou senha inválidos."}
        )

    payload = {"sub": str(usuario.id)}
    access_token = criar_access_token(payload, expires_delta=timedelta(minutes=60))
    refresh_token = criar_access_token(payload, expires_delta=timedelta(days=30))

    response = {"mensagem": "Entrada efetuada com sucesso.", "access_token": access_token, "refresh_token": refresh_token}
    return response

@router.get("/refresh")
def refresh(
    token_data = Depends(get_current_refresh),
):
    # token_data["sub"] contém o user_id
    new_access = criar_access_token(
        {"sub": token_data["sub"]},
        expires_delta=timedelta(minutes=60)
    )
    response = {"mensagem": "Access token renovado com sucesso.", "access_token": new_access}
    return response

# --- Consulta dados do usuário logado ---
@protected_router.get("/dados", response_model=DadosResponseDcto)
def dados(request: Request, db: Session = Depends(get_db)):
    user_id = request.state.user_id  # já validado pelo middleware
    usuario = db.query(Usuario).get(user_id)
    pessoa  = db.query(Pessoa).get(usuario.id_pessoa) if usuario else None

    if not usuario or not pessoa:
        raise HTTPException(404, "Usuário ou pessoa não encontrados.")

    return {"usuario": usuario, "pessoa": pessoa}

# --- Logout ---
@protected_router.delete("/sair")
def sair(request: Request, db: Session = Depends(get_db)):
    jti = request.state.jti
    if jti:
        adicionar_jti_na_blacklist(jti, db)

    response = {"mensagem": "Saída realizada com sucesso."}
    return response
