from datetime import timezone
from sqlalchemy import Boolean, Column, DateTime, Integer, String
from sqlalchemy.orm import relationship
from ..database import Base

class Admins(Base):
    __tablename__ = "project"

    id = Column(Integer, primary_key=True)
    first_name = Column(String, index=True)
    last_name = Column(String, index=True)
    email = Column(String, unique=True, index=True)    
    is_active = Column(Boolean, default=True)