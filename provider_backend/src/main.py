from fastapi import FastAPI
from models.admin_models import Base as admin_model
from models.tenant_models import Base
from models.otp_models import Base as otp_model
from database import engine
from routers.admin_routes import router as admin_router
from routers.tenant_routes import router as auth_router

app = FastAPI()

admin_model.metadata.create_all(bind=engine)
Base.metadata.create_all(bind=engine)  # Create tables
otp_model.metadata.create_all(bind=engine)  # Create tables

# Enregistrez le routeur des projets
# app.include_router(subscriber_router)
app.include_router(auth_router)
app.include_router(admin_router)