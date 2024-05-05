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
    role_id = Column(Integer, ForeignKey('roles.id'))
    role = relationship("AdminRole", back_populates="credentials")
    admin = relationship("AdminInfos", back_populates="credentials")
    
class AdminRole(Base):
    __tablename__ = 'roles'

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    credentials = relationship("AdminCredential", back_populates="role")
    permissions = relationship("Permission", back_populates="role")

class Permission(Base):
    __tablename__ = 'permissions'

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    role_id = Column(Integer, ForeignKey('roles.id'))
    role = relationship('AdminRole', back_populates='permissions')