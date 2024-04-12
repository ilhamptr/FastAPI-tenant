from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException
from src.schemas.project_schema import ProjectSchema
from src.models.project_model import Project
from src.database import SessionLocal, engine
from sqlalchemy.orm import Session

router = APIRouter()

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]