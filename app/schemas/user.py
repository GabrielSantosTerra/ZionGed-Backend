from pydantic import BaseModel, EmailStr
from typing import Optional

# Usuario
class UserCreateDcto(BaseModel):
    nome: str
    email: EmailStr
    senha: str
    cpf_cnpj: str
    tipo_pessoa: str

class UserLoginDcto(BaseModel):
    email: EmailStr
    senha: str

class UserResponseDcto(BaseModel):
    id: int
    email: str

    class Config:
        orm_mode = True

class PessoaResponseDcto(BaseModel):
    id: int
    nome: str
    cpf_cnpj: Optional[str]

    class Config:
        orm_mode = True

class CadastroResponseDcto(BaseModel):
    usuario: UserResponseDcto
    pessoa: PessoaResponseDcto

    class Config:
        orm_mode = True

class DadosResponseDcto(BaseModel):
    usuario: UserResponseDcto
    pessoa: PessoaResponseDcto

    class Config:
        orm_mode = True