# Create model attributes/columns

from datetime import datetime
from sqlalchemy import Boolean, Column, DateTime, Integer, String
from sqlalchemy.orm import relationship
from database import Base
from sqlalchemy import ForeignKey

class TenantInfos(Base):
    __tablename__ = "tenant_infos"

    id = Column(Integer, primary_key=True, autoincrement=True)
    first_name = Column(String, index=True)
    last_name = Column(String, index=True)    
    # email = Column(String, unique=True, index=True)
    subdomain = Column(String, unique=True, index=True)
    registered_at = Column(DateTime, default=datetime.now())
    is_active = Column(Boolean, default=True)
    tenant_id = Column(Integer, ForeignKey('tenant_credential.id'), unique=True)
    credentials = relationship("TenantCredential", back_populates="tenant")

class TenantCredential(Base):
    __tablename__ = "tenant_credential"

    id = Column(Integer, primary_key=True, autoincrement=True)
    password = Column(String)
    email = Column(String,unique=True,index=True)
    # salt = Column(String)
    tenant = relationship("TenantInfos", back_populates="credentials")