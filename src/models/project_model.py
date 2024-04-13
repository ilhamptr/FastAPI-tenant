# Create model attributes/columns

from sqlalchemy import Column, Integer, String
from ..database import Base

class Project(Base):
    __tablename__ = "project"

    id = Column(Integer, primary_key=True)
    name = Column(String(100), unique=True, index=True)
    key = Column(String(10), unique=True, index=True)
    description = Column(String, index=True)