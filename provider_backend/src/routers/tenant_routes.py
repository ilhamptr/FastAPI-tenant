# fastapi imports
from fastapi import APIRouter, Depends, HTTPException,status
from fastapi.security import OAuth2PasswordBearer,OAuth2PasswordRequestForm
# 
# typing and schemas
from typing import Annotated
from schemas.subscribers_schema import Token,CreateUserRequest
# 
# model and database imports
from models.tenant_models import Tenant
from database import SessionLocal, engine
from sqlalchemy.orm import Session
# 
# jwt and password encryption
from passlib.context import CryptContext
from jose import jwt,JWTError
from datetime import timedelta,datetime
# 
# secret key and credentials
from dotenv import load_dotenv
import os
# 


# Load environment variables from .env file
load_dotenv()

router = APIRouter(tags=["auth"])

SECRET_KEY= os.getenv("SECRET_KEY")
ALGORITHM= os.getenv("ALGORITHM")

expires_delta = timedelta(minutes=int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES")))

bcrypt_context = CryptContext(schemes=['bcrypt'],deprecated='auto')
oauth2_bearer = OAuth2PasswordBearer(tokenUrl='token',scheme_name="tenant_validation")

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def get_current_tenant(token:Annotated[str,Depends(oauth2_bearer)]):
    try:
        payload = jwt.decode(token,SECRET_KEY,algorithms=[ALGORITHM])
        tenantname: str = payload.get("sub")
        tenant_id: int = payload.get("id")
        if None in (tenantname, tenant_id):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Could not validate tenant")
        return {'tenantname':tenantname,'id':tenant_id}
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Could not validate tenant")

db_dependency = Annotated[Session, Depends(get_db)]
tenant_dependency =Annotated[dict,Depends(get_current_tenant)]

@router.post("/register/",status_code=status.HTTP_201_CREATED, tags=["auth"])
async def create_tenant(db:db_dependency,create_tenant_request:CreateUserRequest):
    create_tenant = Tenant(
        first_name = create_tenant_request.first_name,
        last_name = create_tenant_request.last_name,
        password = bcrypt_context.hash(create_tenant_request.password),
        email = create_tenant_request.email,
        subdomain = create_tenant_request.subdomain,
    )
    db.add(create_tenant)
    db.commit()
        
@router.post("/token/",response_model=Token, tags=["auth"])
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm,Depends()], db:db_dependency):
    tenant = authenticate_tenant(form_data.tenantname, form_data.password,db)
    if not tenant:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate tenant.")
    token = create_access_token(tenant.email,tenant.id, expires_delta)
    
    return {"access_token":token,"token_type":"bearer"}

@router.get("/",status_code=status.HTTP_200_OK, tags=["auth"])
async def tenant(tenant:tenant_dependency,db:db_dependency):
    if tenant is None:
        raise HTTPException(status_code=401,detail="Authentication failed")
    return {"tenant":tenant}

def authenticate_tenant(email:str, password:str,db):
    tenant = db.query(Tenant).filter(Tenant.email == email).first()
    if not tenant:
        return False
    if not bcrypt_context.verify(password, tenant.password):
        return False
    return tenant

def create_access_token(email:str, tenant_id:int, expires_delta:timedelta):
    encode = {"sub":email,"id":tenant_id}
    expires = datetime.now() + expires_delta
    encode.update({'exp':expires})
    return jwt.encode(encode,SECRET_KEY,algorithm=ALGORITHM)
