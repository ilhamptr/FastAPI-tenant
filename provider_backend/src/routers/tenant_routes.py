# fastapi imports
from fastapi import APIRouter, Depends, HTTPException,status
from fastapi.security import OAuth2PasswordBearer,OAuth2PasswordRequestForm
# 
# typing and schemas
from typing import Annotated
from schemas.subscribers_schema import Token,CreateUserRequest,TenantCredentialRequest,VerifyOTP
# 
# model and database imports
from models.tenant_models import TenantInfos,TenantCredential
from models.otp_models import OTP
from database import SessionLocal, engine
from sqlalchemy.orm import Session
from sqlalchemy import or_
# 
# jwt and password encryption
from passlib.context import CryptContext
from jose import jwt,JWTError
from datetime import timedelta,datetime
# 
# secret key and credentials
from dotenv import load_dotenv
import os
import secrets
# 

# otp imports
from emailotp import emailotp
import pyotp
# 


# Load environment variables from .env file
load_dotenv()

router = APIRouter(tags=["auth"])

SECRET_KEY= os.getenv("SECRET_KEY")
ALGORITHM= os.getenv("ALGORITHM")

time_step = int(os.getenv("OTP_TIME_STEP"))
expires_delta = timedelta(minutes=int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES")))
key = os.getenv("OTP_KEY")


bcrypt_context = CryptContext(schemes=['bcrypt'],deprecated='auto')
oauth2_bearer = OAuth2PasswordBearer(tokenUrl='token',scheme_name="tenant_validation")

totp = pyotp.TOTP(key,interval=time_step)
emailotp = emailotp()


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

@router.post("/send_otp/",status_code=status.HTTP_200_OK, tags=["auth"])
async def send_otp(db:db_dependency,create_tenant_request:CreateUserRequest):
    tenant = db.query(TenantCredential).filter(TenantCredential.email == create_tenant_request.email).first()
    if tenant:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User already exist.")
    otpcode = totp.now()
    responseFromEmailOtp = emailotp.sendOtp(create_tenant_request.email, otpcode)
    create_otp = OTP(
        owner = create_tenant_request.email,
        otp = otpcode,
        expiration=  datetime.now() + timedelta(minutes=4)
    )
    db.add(create_otp)
    db.commit()
        
    return {"message":"otp sent successfully"}
        
@router.post("/register/")
async def register(db:db_dependency,create_tenant_request:VerifyOTP):
    user_otp = db.query(OTP).filter(OTP.owner == create_tenant_request.email,OTP.otp == create_tenant_request.otp,OTP.expiration > datetime.now()).first()  # Filter by expiration not yet expired).first()
    if not user_otp:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="OTP not found or expired")
    
    create_tenant = TenantCredential(
        password = bcrypt_context.hash(create_tenant_request.password),
        email = create_tenant_request.email
    )
    db.add(create_tenant)
    db.commit()
    return {"message":"otp verified successfully"}
    
@router.post("/token/",response_model=Token, tags=["auth"])
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm,Depends()], db:db_dependency):
    tenant = authenticate_tenant(form_data.username, form_data.password,db)
    print(tenant)
    if not tenant:
        print(tenant)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate tenant.")
    token = create_access_token(tenant.email,tenant.id, expires_delta)
    
    return {"access_token":token,"token_type":"bearer"}

@router.post("/create_tenant_info/",status_code=status.HTTP_201_CREATED, tags=["auth"])
async def create_tenant_info(current_tenant:tenant_dependency,tenant_credential:TenantCredentialRequest,db:db_dependency):
    if current_tenant is None:
        raise HTTPException(status_code=401,detail="Authentication failed")
    tenant = db.query(TenantInfos).filter(or_(TenantInfos.subdomain == tenant_credential.subdomain, TenantInfos.tenant_id == current_tenant["id"])).first()
    if tenant:
        if tenant.subdomain == tenant_credential.subdomain:
            raise HTTPException(status_code=409, detail="Subdomain already exists.")
        elif tenant.tenant_id == current_tenant["id"]:
            raise HTTPException(status_code=409, detail="Tenant already has a subdomain.")
    tenant_info = TenantInfos(
        first_name = tenant_credential.first_name,
        last_name = tenant_credential.last_name,
        subdomain = f"{tenant_credential.subdomain}.yoursite.com",
        tenant_id = current_tenant["id"]
    )
    db.add(tenant_info)
    db.commit()
    return {"current_tenant":tenant}


@router.get("/",status_code=status.HTTP_200_OK, tags=["auth"])
async def tenant(tenant:tenant_dependency,db:db_dependency):
    if tenant is None:
        raise HTTPException(status_code=401,detail="Authentication failed")
    return {"tenant":tenant}

def authenticate_tenant(email:str, password:str,db):
    tenant = db.query(TenantCredential).filter(TenantCredential.email == email).first()
    # Hash the provided password with the retrieved salt
    if not tenant:
        return False
    if not bcrypt_context.verify(password,tenant.password):
        return False
    return tenant

def create_access_token(email:str, tenant_id:int, expires_delta:timedelta):
    encode = {"sub":email,"id":tenant_id}
    expires = datetime.now() + expires_delta
    encode.update({'exp':expires})
    return jwt.encode(encode,SECRET_KEY,algorithm=ALGORITHM)
