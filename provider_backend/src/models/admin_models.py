from sqlalchemy import Boolean, Column, Integer, String
from sqlalchemy.orm import relationship
from database import Base

from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship

class AdminInfos(Base):
    __tablename__ = "admin_infos"

    id = Column(Integer, primary_key=True, autoincrement=True)
    first_name = Column(String, index=True)
    last_name = Column(String, index=True)
    is_active = Column(Boolean, default=True)
    admin_id = Column(Integer, ForeignKey('admin_credential.id'), unique=True)
    credentials = relationship("AdminCredential", back_populates="admin")

class AdminCredential(Base):
    __tablename__ = "admin_credential"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)
    admin = relationship("AdminInfos", back_populates="credentials")