from app.database.connection import Base
from sqlalchemy import Column, String, ForeignKey, Integer
from sqlalchemy.orm import relationship, declarative_base

class Pessoa(Base):
    __tablename__ = 'tb_pessoas'

    id = Column(Integer, primary_key=True, index=True)
    nome = Column(String(255), nullable=True)
    cpf_cnpj = Column(String(20), nullable=True, unique=True)
    tipo_pessoa = Column(String(20), nullable=True)

    usuario = relationship("Usuario", back_populates="pessoa", uselist=False)

class Usuario(Base):
    __tablename__ = "tb_usuarios"

    id = Column(Integer, primary_key=True, index=True)
    id_pessoa = Column(Integer, ForeignKey("tb_pessoas.id"), nullable=False)
    email = Column(String, unique=True, nullable=False)
    senha = Column(String, nullable=False)

    pessoa = relationship("Pessoa", back_populates="usuario")