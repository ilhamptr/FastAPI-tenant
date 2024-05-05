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
from schemas.admins_schema import Status,Email,OTPVerification,CreateAdmin
# 
# model and database imports
from sqlalchemy.orm import Session
from models.admin_models import AdminCredential,AdminInfos,Permission,AdminRole
from models.tenant_models import TenantInfos,TenantCredential
from models.otp_models import OTP
from sqlalchemy import func
from database import SessionLocal, engine
# for secret keys and secret credentials
import os
from dotenv import load_dotenv
# 
from passlib.context import CryptContext
import re

load_dotenv()
router = APIRouter(tags=["admin"])

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")

expires_delta = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))

key = os.getenv("OTP_KEY")

oauth2_bearer_admin = OAuth2PasswordBearer(tokenUrl='otp_verification',scheme_name="otp_verification")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
db_dependency = Annotated[Session, Depends(get_db)]

totp = pyotp.TOTP(key)
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
        role_id: int = payload.get("role_id")
        if username is None or user_id is None or role_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Could not validate user")
        return {'username':username,'id':user_id,'role_id':role_id}
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Could not validate user")

def create_access_token(email:str,user_id:int,role_id, expires_delta:timedelta):
    encode = {"sub":email,"id":user_id,"role_id":role_id}
    expires = datetime.now() + expires_delta
    encode.update({'exp':expires})
    return jwt.encode(encode,SECRET_KEY,algorithm=ALGORITHM)

user_dependency =Annotated[dict,Depends(get_current_user)]

@router.post("/create_admin/",status_code=status.HTTP_201_CREATED, tags=["admin"])
async def create_admin(admin_request:CreateAdmin,admin:user_dependency,db:db_dependency):
# Define a regular expression pattern for password validation
    pattern = r'(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>])[A-Za-z\d!@#$%^&*(),.?":{}|<>]{8,}'
    # Check if the password matches the pattern
    if not re.match(pattern, admin_request.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Your password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character")
    role_id = admin["role_id"]
    permission = db.query(Permission).filter(Permission.role_id == role_id).all()
    permission_names = [permission.name for permission in permission]
    if not "create_admin" in permission_names:
        raise HTTPException(status_code=401,detail="You are unauthorized to make this request")
    role = db.query(AdminRole).filter(func.lower(AdminRole.name) == func.lower(admin_request.role_name)).first()
    if not role:
        raise HTTPException(status_code=404,detail="role is not available")    
    create_tenant = AdminCredential(
        password = bcrypt_context.hash(admin_request.password),
        email = admin_request.email,
        role_id = role.id
    )
    db.add(create_tenant)
    db.commit()
    return {"message":"new admin has been created"}
    
@router.post("/otp_sending/",status_code=status.HTTP_200_OK, tags=["admin"])
async def otp(form_data: Annotated[OAuth2PasswordRequestForm,Depends()],db:db_dependency):
    # Verify the OTP entered by the user
    admin = authenticate_admin(form_data.username,form_data.password,db)
    if not admin:
        raise HTTPException(status_code=404,detail="Admin not available")
    otpcode = totp.now()
    # Send the new OTP via email
    response_from_emailotp = emailotp.sendOtp(form_data.username, otpcode)
    create_otp = OTP(
        owner = form_data.username,
        otp = otpcode,
        expiration=  datetime.now() + timedelta(minutes=4)
    )
    db.add(create_otp)
    db.commit()
    return {"message": "OTP sent successfully"}
    
@router.post("/otp_verification/",status_code=status.HTTP_200_OK, tags=["admin"])
async def otp_verification(form_data:OTPVerification,db:db_dependency):
    admin = db.query(AdminCredential).filter(AdminCredential.email == form_data.email).first()
    if not admin:
        raise HTTPException(status_code=404,detail="Admin not available")
    user_otp = db.query(OTP).filter(OTP.owner == form_data.email,OTP.otp == form_data.otp,OTP.expiration > datetime.now()).first()  # Filter by expiration not yet expired).first()
    if not user_otp:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="OTP not found or expired")
    
    # Generate a new OTP
    token = create_access_token(admin.email,admin.id,admin.role_id, timedelta(minutes=expires_delta))
    return {"access_token":token,"token_type":"bearer"}
    
@router.get("/current_admin/",status_code=status.HTTP_200_OK, tags=["admin"])
async def admin_data(admin:user_dependency,db:db_dependency):
    if admin is None:
        raise HTTPException(status_code=401,detail="Authentication failed")
    return {"admin":admin['username']}

@router.get("/read_admin/",status_code=status.HTTP_200_OK,tags=["admin"])
async def admin_list(admin:user_dependency,db:db_dependency):
    if admin is None:
        raise HTTPException(status_code=401,detail="Authentication failed")
    role_id = admin["role_id"]
    permission = db.query(Permission).filter(Permission.role_id == role_id).all()
    permission_names = [permission.name for permission in permission]
    if not "read_admin" in permission_names:
        raise HTTPException(status_code=401,detail="You are unauthorized to make this request")
    # Fetch admin information
    admins = db.query(AdminInfos).all()
    # Prepare response data
    admin_data = []
    for admin_info in admins:
        admin_dict = {
            "id": admin_info.id,
            "first_name": admin_info.first_name,
            "last_name": admin_info.last_name,
            "is_active": admin_info.is_active,
            "credentials": []  # Initialize an empty list to store credentials
        }
        
        # Fetch credentials for the admin
        credential = admin_info.credentials
        if credential:  # Check if credential exists
            admin_dict["credentials"].append({
                "id": credential.id,
                "email": credential.email
            })
        admin_data.append(admin_dict)
    
    return {"admins": admin_data}

@router.delete("/delete_admin/{admin_id}",status_code=status.HTTP_200_OK,tags=["admin"])
async def delete_admin(admin_id:int,admin:user_dependency,db:db_dependency):
    if admin is None:
        raise HTTPException(status_code=401,detail="Authentication failed")
    role_id = admin["role_id"]
    permission = db.query(Permission).filter(Permission.role_id == role_id).all()
    permission_names = [permission.name for permission in permission]
    if not "delete_admin" in permission_names:
        raise HTTPException(status_code=401,detail="You are unauthorized to make this request")
     # Also delete admin's entry from AdminCredential if exists
    admin_info = db.query(AdminInfos).filter(AdminInfos.admin_id == admin_id).first()
    if admin_info:
        db.delete(admin_credential)
        db.commit()
    admin_credential = db.query(AdminCredential).filter(AdminCredential.id == admin_id).first()
    if admin_credential:
        db.delete(admin_credential)
        db.commit()
    return {"message":"admin has been deleted"}
    