from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException
from provider_backend.src.schemas.subscribers_schema import ProjectSchema
from provider_backend.src.models.subscribers_model import Project
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