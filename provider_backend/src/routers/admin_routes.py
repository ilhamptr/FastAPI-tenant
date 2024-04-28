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
from schemas.admins_schema import Status,Email
# 
# model and database imports
from sqlalchemy.orm import Session
from models.admin_models import Admin
from models.tenant_models import Tenant
from database import SessionLocal, engine
# for secret keys and secret credentials
import os
from dotenv import load_dotenv
# 


load_dotenv()
router = APIRouter(tags=["admin"])

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")

time_step = int(os.getenv("OTP_TIME_STEP"))
expires_delta = timedelta(minutes=int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES")))

key = os.getenv("OTP_KEY")

oauth2_bearer_admin = OAuth2PasswordBearer(tokenUrl='otp_validation',scheme_name="admin_validation")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
db_dependency = Annotated[Session, Depends(get_db)]

totp = pyotp.TOTP(key,interval=time_step)
emailotp = emailotp()

def authenticate_user(email:str,password:str,db):
    user = db.query(Admin).filter(Admin.email == email).first()
    if not user:
        return False
    if totp.verify(password) == False:
        print("something wrong")
        raise HTTPException(status_code=401,detail="Invalid otp")
    return user

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

@router.post("/otp_validation/")
async def otp(form_data: Annotated[OAuth2PasswordRequestForm,Depends()],db:db_dependency):
    # Verify the OTP entered by the user
    admin = authenticate_user(form_data.username,form_data.password,db)
    if not admin:
        raise HTTPException(status_code=404,detail="Admin not available")
    token = create_access_token(admin.email,admin.id, timedelta(expires_delta))
    return {"access_token":token,"token_type":"bearer"}

@router.post("/email/")
async def email(email:Email,db:db_dependency):
    admin = db.query(Admin).filter(Admin.email == email.email).first()
    if not admin:
        raise HTTPException(status_code=404,detail="Admin not available")
    # Generate a new OTP
    otpcode = totp.now()
    print("New OTP generated:", otpcode)

    # Send the new OTP via email
    response_from_emailotp = emailotp.sendOtp(email.email, otpcode)
    print(response_from_emailotp["message"])

    return {"message": "OTP sent successfully"}

@router.get("/current_admin/",status_code=status.HTTP_200_OK, tags=["admin"])
async def admin_data(admin:user_dependency,db:db_dependency):
    if admin is None:
        raise HTTPException(status_code=401,detail="Authentication failed")
    return {"admin":admin['username']}

@router.get("/subscribers_list/",status_code=status.HTTP_200_OK,tags=["admin"])
async def subscribers_list(admin:user_dependency,db:db_dependency):
    if admin is None:
        raise HTTPException(status_code=401,detail="Authentication failed")
    user = db.query(Tenant).all()
    return {"user":user}

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