from fastapi import FastAPI
from provider_backend.src.models.subscribers_model import Base
from src.database import engine
from provider_backend.src.routers.subscribers_routes import router as project_router

app = FastAPI()

Base.metadata.create_all(bind=engine)  # Create tables

# Enregistrez le routeur des projets
app.include_router(project_router)