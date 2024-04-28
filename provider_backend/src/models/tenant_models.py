# Create model attributes/columns

from datetime import datetime
from sqlalchemy import Boolean, Column, DateTime, Integer, String
from sqlalchemy.orm import relationship
from database import Base

class Tenant(Base):
    __tablename__ = "tenant"

    id = Column(Integer, primary_key=True,autoincrement=True)
    first_name = Column(String, index=True)
    last_name = Column(String, index=True)
    password = Column(String, index=True)
    email = Column(String, unique=True, index=True)
    subdomain = Column(String, unique=True, index=True)
    registred_at = Column(DateTime, default=datetime.now())
    is_active = Column(Boolean, default=True)