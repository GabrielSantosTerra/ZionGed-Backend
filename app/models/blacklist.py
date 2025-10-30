from app.database.connection import Base
from sqlalchemy import Column, Integer, String, DateTime, func

class BlacklistToken(Base):
    __tablename__ = "tb_lista_negra"

    id = Column(Integer, primary_key=True, index=True)
    jti = Column(String, nullable=False, unique=True)
    data_insercao = Column(DateTime(), default=func.now())
