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
from sqlalchemy import or_,func
# 
# jwt and password encryption
from passlib.context import CryptContext
from jose import jwt,JWTError
from datetime import timedelta,datetime
import re
# 
# secret key and credentials
from dotenv import load_dotenv
import os
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

expires_delta = timedelta(minutes=int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES")))
key = os.getenv("OTP_KEY")


bcrypt_context = CryptContext(schemes=['bcrypt'],deprecated='auto')
oauth2_bearer = OAuth2PasswordBearer(tokenUrl='token',scheme_name="tenant_validation")

totp = pyotp.TOTP(key)
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

# Endpoint for sending OTP to tenant for registration
@router.post("/tenant_send_otp/", status_code=status.HTTP_200_OK, tags=["auth"])
async def send_otp(db: db_dependency, create_tenant_request: CreateUserRequest):
    # Check if tenant with provided email already exists
    tenant = db.query(TenantCredential).filter(func.lower(TenantCredential.email) == func.lower(create_tenant_request.email)).first()
    if tenant:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User already exists.")
    
    # Generate OTP
    otpcode = totp.now()
    
    # Send OTP via email
    response_from_email_otp = emailotp.sendOtp(create_tenant_request.email, otpcode)
    
    # Create OTP entry in database
    create_otp = OTP(
        owner=create_tenant_request.email,
        otp=otpcode,
        expiration=datetime.now() + timedelta(minutes=4)
    )
    db.add(create_otp)
    db.commit()
    
    # Return success message
    return {"message": "OTP sent successfully"}

        
# Endpoint for registering a tenant after OTP verification
@router.post("/tenant_register/{tenant_email}/", status_code=status.HTTP_201_CREATED, tags=["auth"])
async def register(db: db_dependency, create_tenant_request: VerifyOTP, tenant_email: str):
    # Check if the provided OTP is valid and not expired
    user_otp = db.query(OTP).filter(OTP.owner == tenant_email, OTP.otp == create_tenant_request.otp, OTP.expiration > datetime.now()).first()
    if not user_otp:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="OTP not found or expired")
    
    # Define a regular expression pattern for password validation
    pattern = r'(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>])[A-Za-z\d!@#$%^&*(),.?":{}|<>]{8,}'
    
    # Check if the password matches the pattern
    if not re.match(pattern, create_tenant_request.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Your password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character")
    
    # Create a new TenantCredential instance with hashed password
    create_tenant = TenantCredential(
        password=bcrypt_context.hash(create_tenant_request.password),
        email=tenant_email
    )
    
    # Add the new tenant to the database
    db.add(create_tenant)
    db.commit()
    
    # Return success message
    return {"message": "OTP verified successfully, tenant is added"}

# Endpoint for generating access token for tenant login
@router.post("/token/",response_model=Token, tags=["auth"])
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm,Depends()], db:db_dependency):
    # Authenticate the tenant using provided credentials
    tenant = authenticate_tenant(form_data.username, form_data.password,db)
    # If authentication fails, raise unauthorized exception
    if not tenant:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate tenant.")
    # Generate access token for the authenticated tenant
    token = create_access_token(tenant.email,tenant.id, expires_delta)
    # Return the access token along with token type
    return {"access_token":token,"token_type":"bearer"}

# Endpoint for creating tenant information
@router.post("/create_tenant_info/",status_code=status.HTTP_201_CREATED, tags=["auth"])
async def create_tenant_info(current_tenant:tenant_dependency,tenant_credential:TenantCredentialRequest,db:db_dependency):
    # Checking if current tenant is authenticated
    if current_tenant is None:
        raise HTTPException(status_code=401,detail="Authentication failed")
    # Querying the database to check if the provided subdomain or tenant ID already exists
    tenant = db.query(TenantInfos).filter(or_(TenantInfos.subdomain == tenant_credential.subdomain, TenantInfos.tenant_id == current_tenant["id"])).first()
    # If a tenant with the provided subdomain or tenant ID already exists, raise a conflict exception
    if tenant:
        if tenant.subdomain == tenant_credential.subdomain:
            raise HTTPException(status_code=409, detail="Subdomain already exists.")
        elif tenant.tenant_id == current_tenant["id"]:
            raise HTTPException(status_code=409, detail="Tenant already has a subdomain.")
    # Create a new TenantInfos instance
    tenant_info = TenantInfos(
        first_name = tenant_credential.first_name,
        last_name = tenant_credential.last_name,
        subdomain = f"{tenant_credential.subdomain}.yoursite.com",
        tenant_id = current_tenant["id"]
    )
    # Add the new tenant information to the database
    db.add(tenant_info)
    db.commit()
    return {"message": "tenant info is successfully added"}

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
