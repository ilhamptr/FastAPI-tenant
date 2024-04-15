# Create model attributes/columns

from datetime import timezone
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import relationship
from ..database import Base

class Project(Base):
    __tablename__ = "project"

    id = Column(Integer, primary_key=True)
    icon_path = Column(String, index=True)
    name = Column(String(100), unique=True, index=True)
    key = Column(String(10), unique=True, index=True)
    description = Column(String, index=True)
    lead_id = Column(Integer, ForeignKey('user.id'))  # ForeignKey to User model
    lead = relationship("User", back_populates="projects")  # Assuming User model has 'projects' relationship
    created_at = Column(DateTime, default=timezone.utc)