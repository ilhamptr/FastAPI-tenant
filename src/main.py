from fastapi import FastAPI
from src.models.project_model import Base
from src.database import engine
from src.routers.project_routes import router as project_router

from src.schemas.project_schema import ProjectSchema

app = FastAPI()

Base.metadata.create_all(bind=engine)  # Create tables

# Enregistrez le routeur des projets
app.include_router(project_router)