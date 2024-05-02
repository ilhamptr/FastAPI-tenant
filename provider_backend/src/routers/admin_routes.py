# fastapi imports
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
# 
# jwt import
from jose import jwt, JWTError
# otp imports
from datetime import timedelta, datetime
from emailotp import emailotp
import pyotp
# 
# typing and schemas
from typing import Annotated
from schemas.admins_schema import Status,Email,CustomOAuth2PasswordRequestForm
# 
# model and database imports
from sqlalchemy.orm import Session
from models.admin_models import AdminCredential,AdminInfos
from models.tenant_models import TenantInfos,TenantCredential
from models.otp_models import OTP
from database import SessionLocal, engine
# for secret keys and secret credentials
import os
from dotenv import load_dotenv
# 
from passlib.context import CryptContext

from pydantic import BaseModel, Field
from fastapi.security.oauth2 import OAuth2PasswordRequestForm

class CustomOAuth2PasswordRequestForm(OAuth2PasswordRequestForm):
    otp: str = Field(..., description="One-time password (OTP)")

load_dotenv()
router = APIRouter(tags=["admin"])

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")

time_step = int(os.getenv("OTP_TIME_STEP"))
expires_delta = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))

key = os.getenv("OTP_KEY")

oauth2_bearer_admin = OAuth2PasswordBearer(tokenUrl='admin_validation',scheme_name="admin_validation")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
db_dependency = Annotated[Session, Depends(get_db)]

totp = pyotp.TOTP(key,interval=time_step)
emailotp = emailotp()
bcrypt_context = CryptContext(schemes=['bcrypt'],deprecated='auto')

def authenticate_admin(email:str,password:str,db):
    admin = db.query(AdminCredential).filter(AdminCredential.email == email).first()
    # Hash the provided password with the retrieved salt
    if not admin:
        return False
    if not bcrypt_context.verify(password,admin.password):
        return False
    return admin

async def get_current_user(token:Annotated[str,Depends(oauth2_bearer_admin)]):
    try:
        payload = jwt.decode(token,SECRET_KEY,algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        user_id: int = payload.get("id")
        if username is None or user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Could not validate user")
        return {'username':username,'id':user_id}
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Could not validate user")

def create_access_token(email:str,user_id:int, expires_delta:timedelta):
    encode = {"sub":email,"id":user_id}
    expires = datetime.now() + expires_delta
    encode.update({'exp':expires})
    return jwt.encode(encode,SECRET_KEY,algorithm=ALGORITHM)

user_dependency =Annotated[dict,Depends(get_current_user)]

# @router.post("/register_admin/")
# async def verify_otp(db:db_dependency):
#     create_admin = AdminCredential(
#         password = bcrypt_context.hash("moonh3h3"),
#         email = "ilhamptr007@gmail.com"
#     )
#     db.add(create_admin)
#     db.commit()
#     return {"message":"otp verified successfully"}
    

@router.post("/otp_sending/")
async def otp(form_data: Annotated[OAuth2PasswordRequestForm,Depends()],db:db_dependency):
    # Verify the OTP entered by the user
    admin = authenticate_admin(form_data.username,form_data.password,db)
    if not admin:
        raise HTTPException(status_code=404,detail="Admin not available")
    otpcode = totp.now()
    print("New OTP generated:", otpcode)

    # Send the new OTP via email
    response_from_emailotp = emailotp.sendOtp(form_data.username, otpcode)
    print(response_from_emailotp["message"])
    create_otp = OTP(
        owner = form_data.username,
        otp = otpcode,
        expiration=  datetime.now() + timedelta(minutes=4)
    )
    db.add(create_otp)
    db.commit()
    return {"message": "OTP sent successfully"}
    
@router.post("/otp_verification/")
async def otp_verification(form_data:Annotated[CustomOAuth2PasswordRequestForm,Depends()],db:db_dependency):
    admin = db.query(AdminCredential).filter(AdminCredential.email == form_data.email).first()
    if not admin:
        raise HTTPException(status_code=404,detail="Admin not available")
    # Generate a new OTP
    # token = create_access_token(admin.email,admin.id, timedelta(minutes=expires_delta))
    # return {"access_token":token,"token_type":"bearer"}
    
@router.get("/current_admin/",status_code=status.HTTP_200_OK, tags=["admin"])
async def admin_data(admin:user_dependency,db:db_dependency):
    if admin is None:
        raise HTTPException(status_code=401,detail="Authentication failed")
    return {"admin":admin['username']}

@router.get("/subscribers_list/",status_code=status.HTTP_200_OK,tags=["admin"])
async def subscribers_list(admin:user_dependency,db:db_dependency):
    if admin is None:
        raise HTTPException(status_code=401,detail="Authentication failed")
    tenants = db.query(Tenant).all()
    return {"tenants":tenants}

@router.patch("/subscriber_status/",status_code=status.HTTP_200_OK, tags=["admin"])
async def subscriber_status(admin:user_dependency,user:Status,db:db_dependency):
    if admin is None:
        raise HTTPException(status_code=401,detail="Authentication failed")
    user = db.query(Tenant).filter(Tenant.email == user.username).first()
    if user.is_active:
        user.is_active = False
        db.commit()
        return {"message":"subscriber has been deactivated"}
    user.is_active = True
    db.commit()
    return {"message": "subscriber has been activated"}