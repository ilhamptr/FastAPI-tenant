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
from schemas.admins_schema import OTPVerification,CreateAdmin,AdminInfosSchema,TenantInfosSchema
# 
# model and database imports
from sqlalchemy.orm import Session
from models.admin_models import AdminCredential,AdminInfos,Permission,AdminRole
from models.tenant_models import TenantCredential,TenantInfos
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

# to create admin while you are authenticated as an admin that can create another admin
@router.post("/create_admin/",status_code=status.HTTP_201_CREATED, tags=["admin"])
async def create_admin(admin_request:CreateAdmin,admin:user_dependency,db:db_dependency):
# Define a regular expression pattern for password validation
    pattern = r'(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>])[A-Za-z\d!@#$%^&*(),.?":{}|<>]{8,}'
    # Check if the password matches the pattern
    if not re.match(pattern, admin_request.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Your password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character")
    role_id = admin["role_id"]
    # Querying the database to get permissions associated with the admin's role
    permission = db.query(Permission).filter(Permission.role_id == role_id).all()
    permission_names = [permission.name for permission in permission]
    if not "create_admin" in permission_names:
        raise HTTPException(status_code=401,detail="You are unauthorized to make this request")
    # Querying the database to check if the specified role exists
    role = db.query(AdminRole).filter(func.lower(AdminRole.name) == func.lower(admin_request.role_name)).first()
    if not role:
        raise HTTPException(status_code=404,detail="role is not available")   
    # Creating a new AdminCredential instance with hashed password 
    create_tenant = AdminCredential(
        password = bcrypt_context.hash(admin_request.password),
        email = admin_request.email,
        role_id = role.id
    )
    db.add(create_tenant)
    # Committing to save changes to the database
    db.commit()
    return {"message":"new admin has been created"}

# to create admininfo of the admin with id in {admin_id} while you are logged in as an admin that can create admininfo
@router.post("/create_admin_infos/{admin_id}/",status_code=status.HTTP_201_CREATED, tags=["admin"])
async def create_admin(admin_id:int,admin_request:AdminInfosSchema,admin:user_dependency,db:db_dependency):
    # Fetching the role ID of the admin making the request
    role_id = admin["role_id"]
    # Querying the database to get permissions associated with the admin's role
    permission = db.query(Permission).filter(Permission.role_id == role_id).all()
    # Extracting permission names from the query result
    permission_names = [permission.name for permission in permission]
    # Checking if the permission to create admin info is granted to the admin
    if not "create_admin_info" in permission_names:
        # If the permission is not found, raise an unauthorized exception
        raise HTTPException(status_code=401,detail="You are unauthorized to make this request")
    # Creating a new AdminInfos instance with data from the request
    create_tenant_info = AdminInfos(
        first_name = admin_request.first_name,
        last_name = admin_request.last_name,
        is_active = admin_request.is_active,
        admin_id = admin_id
    )
    # Adding the new AdminInfos instance to the database session
    db.add(create_tenant_info)
    # Committing to save changes to the database
    db.commit()
    return {"message":"admin infos has been created"}
    
# to send an OTP to an existed admin for authentication
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
    
# to authenticate otp that was sent to the admin from /otp_sending/ endpoint
@router.post("/otp_verification/{admin_email}/",status_code=status.HTTP_200_OK, tags=["admin"])
async def otp_verification(admin_email:str,form_data:OTPVerification,db:db_dependency):
    # Querying the database to get admin credentials by email
    admin = db.query(AdminCredential).filter(AdminCredential.email == admin_email).first()
    # If admin not found, raise a not found exception
    if not admin:
        raise HTTPException(status_code=404,detail="Admin not available")
    # Querying the database to check if the OTP is valid and not expired
    user_otp = db.query(OTP).filter(OTP.owner == admin_email,OTP.otp == form_data.otp,OTP.expiration > datetime.now()).first()  # Filter by expiration not yet expired).first()
    if not user_otp:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="OTP not found or expired")
    # Generate a new jwt token
    token = create_access_token(admin.email,admin.id,admin.role_id, timedelta(minutes=expires_delta))
    return {"access_token":token,"token_type":"bearer"}

# to get the current admin data based on the jwt token
@router.get("/current_admin/",status_code=status.HTTP_200_OK, tags=["admin"])
async def admin_data(admin:user_dependency,db:db_dependency):
    if admin is None:
        raise HTTPException(status_code=401,detail="Authentication failed")
    return {"admin":admin}

# Endpoint for retrieving all existing admins
@router.get("/read_admin/", status_code=status.HTTP_200_OK, tags=["admin"])
async def admin_list(admin: user_dependency, db: db_dependency):
    # Checking if admin is authenticated
    if admin is None:
        raise HTTPException(status_code=401, detail="Authentication failed")
    
    # Fetching the role ID of the admin making the request
    role_id = admin["role_id"]
    
    # Querying the database to get permissions associated with the admin's role
    permission = db.query(Permission).filter(Permission.role_id == role_id).all()
    
    # Extracting permission names from the query result
    permission_names = [permission.name for permission in permission]
    
    # Checking if the permission to read admin is granted to the admin
    if not "read_admin" in permission_names:
        # If the permission is not found, raise an unauthorized exception
        raise HTTPException(status_code=401, detail="You are unauthorized to make this request")
    
    # Fetching all admin credential from the database
    admins = db.query(AdminCredential).all()
    
    # Prepare response data
    admin_data = []
    
    # Iterate through each admin and gather their credential
    for admin_credential in admins:
        admin_dict = {
        "admin_id": admin_credential.id,
        "email": admin_credential.email,
        "info": []  # Initialize an empty list to store info
    }

    # Fetch info for the admin
    infos = admin_credential.admin  # Note: 'admin' relationship might return multiple objects
    for info in infos:
        admin_dict["info"].append({
            "first_name": info.first_name,
            "last_name": info.last_name,
            "is_active": info.is_active
        })
    
    # Append admin information to the response data
    admin_data.append(admin_dict)
    # Return the response containing admin data
    return {"admins": admin_data}


# Endpoint for deleting an admin
@router.delete("/delete_admin/{admin_id}/", status_code=status.HTTP_204_NO_CONTENT, tags=["admin"])
async def delete_admin(admin_id: int, admin: user_dependency, db: db_dependency):
    # Checking if admin is authenticated
    if admin is None:
        raise HTTPException(status_code=401, detail="Authentication failed")
    
    # Fetching the role ID of the admin making the request
    role_id = admin["role_id"]
    
    # Querying the database to get permissions associated with the admin's role
    permission = db.query(Permission).filter(Permission.role_id == role_id).all()
    
    # Extracting permission names from the query result
    permission_names = [permission.name for permission in permission]
    
    # Checking if the permission to delete admin is granted to the admin
    if not "delete_admin" in permission_names:
        # If the permission is not found, raise an unauthorized exception
        raise HTTPException(status_code=401, detail="You are unauthorized to make this request")
    
    # Querying the database to check if the admin with the provided ID exists
    admin_credential = db.query(AdminCredential).filter(AdminCredential.id == admin_id).first()
    
    # If admin credential not found, raise a not found exception
    if not admin_credential:
        raise HTTPException(status_code=404, detail="Admin not found")
    
    # Querying the database to check if the admin info associated with the admin ID exists
    admin_info = db.query(AdminInfos).filter(AdminInfos.admin_id == admin_id).first()
    
    # If admin info exists, delete the admin credential entry and commit the delete
    if admin_info:
        db.delete(admin_info)
        db.commit()
    
    # Delete admin credential entry if it exists and commit the delete
    if admin_credential:
        db.delete(admin_credential)
        db.commit()


# Endpoint for fetching admin data before updating
@router.get("/update_admin/{admin_id}/")
async def update_admin(admin_id: int, admin: user_dependency, db: db_dependency):
    # Checking if admin is authenticated
    if admin is None:
        raise HTTPException(status_code=401, detail="Authentication failed")
    
    # Fetching the role ID of the admin making the request
    role_id = admin["role_id"]
    
    # Querying the database to get permissions associated with the admin's role
    permission = db.query(Permission).filter(Permission.role_id == role_id).all()
    
    # Extracting permission names from the query result
    permission_names = [permission.name for permission in permission]
    
    # Checking if the permission to update admin is granted to the admin
    if not "update_admin" in permission_names:
        # If the permission is not found, raise an unauthorized exception
        raise HTTPException(status_code=401, detail="You are unauthorized to make this request")
    
    # Querying the database to check if the admin with the provided ID exists
    admin = db.query(AdminInfos).filter(AdminInfos.admin_id == admin_id).all()
    
    # If admin not found, raise a not found exception
    if not admin:
        raise HTTPException(status_code=404, detail="Admin not found")
    
    # Prepare response data
    admin_data = []
    
    # Iterate through each admin and gather their information
    for admin_info in admin:
        admin_dict = {
            "first_name": admin_info.first_name,
            "last_name": admin_info.last_name,
            "is_active": admin_info.is_active,
            "credentials": []  # Initialize an empty list to store credentials
        }
        
        # Fetch credentials for the admin
        credential = admin_info.credentials
        if credential:  # Check if credential exists
            admin_dict["credentials"].append({
                "admin_id": credential.id,
                "email": credential.email
            })
        
        # Append admin information to the response data
        admin_data.append(admin_dict)
    
    # Return the response containing admin data
    return {"admin": admin_data}


# Endpoint for updating an admin
@router.put("/update_admin/{admin_id}/", status_code=status.HTTP_200_OK, tags=["admin"])
async def update_admin(admin_info: AdminInfosSchema, admin_id: int, admin: user_dependency, db: db_dependency):
    # Checking if admin is authenticated
    if admin is None:
        raise HTTPException(status_code=401, detail="Authentication failed")
    
    # Fetching the role ID of the admin making the request
    role_id = admin["role_id"]
    
    # Querying the database to get permissions associated with the admin's role
    permission = db.query(Permission).filter(Permission.role_id == role_id).all()
    
    # Extracting permission names from the query result
    permission_names = [permission.name for permission in permission]
    
    # Checking if the permission to update admin is granted to the admin
    if not "update_admin" in permission_names:
        # If the permission is not found, raise an unauthorized exception
        raise HTTPException(status_code=401, detail="You are unauthorized to make this request")
    
    # Querying the database to get the admin with the provided ID
    admin_data = db.query(AdminInfos).filter(AdminInfos.admin_id == admin_id).first()
    
    # If admin not found, raise a not found exception
    if not admin_data:
        raise HTTPException(status_code=404, detail="Admin not found")
    
    # Updating admin information with the provided data
    admin_data.first_name = admin_info.first_name
    admin_data.last_name = admin_info.last_name
    admin_data.is_active = admin_info.is_active
    
    # Committing to save changes to the database
    db.commit()
    
    # Returning a success message
    return {"message": "Admin has been updated"}

@router.get("/tenant_list/",status_code=status.HTTP_200_OK,tags=["admin"])
async def subscribers_list(admin:user_dependency,db:db_dependency):
   # Checking if admin is authenticated
    if admin is None:
        raise HTTPException(status_code=401, detail="Authentication failed")
    
    # Fetching the role ID of the admin making the request
    role_id = admin["role_id"]
    
    # Querying the database to get permissions associated with the admin's role
    permission = db.query(Permission).filter(Permission.role_id == role_id).all()
    
    # Extracting permission names from the query result
    permission_names = [permission.name for permission in permission]
    
    # Checking if the permission to update admin is granted to the admin
    if not "read_tenant" in permission_names:
        # If the permission is not found, raise an unauthorized exception
        raise HTTPException(status_code=401, detail="You are unauthorized to make this request")
    # Fetching all tenant credential from the database
    tenants = db.query(TenantCredential).all()
    
    # Prepare response data
    tenant_data = []
    
    # Iterate through each tenant and gather their credential
    for tenant_credential in tenants:
        tenant_dict = {
        "tenant_id": tenant_credential.id,
        "email": tenant_credential.email,
        "info": []  # Initialize an empty list to store info
    }

    # Fetch info for the tenatn
    infos = tenant_credential.tenant  # Note: 'tenant' relationship might return multiple objects
    for info in infos:
        tenant_dict["info"].append({
            "first_name": info.first_name,
            "last_name": info.last_name,
            "is_active": info.is_active
        })
    
    # Append tenant information to the response data
    tenant_data.append(tenant_dict)
    # Return the response containing tenants data
    return {"tenants": tenant_data}

@router.patch("/tenant_status/{tenant_id}",status_code=status.HTTP_200_OK, tags=["admin"])
async def subscriber_status(admin:user_dependency,tenant_id:str,db:db_dependency):
    # Checking if admin is authenticated
    if admin is None:
        raise HTTPException(status_code=401, detail="Authentication failed")
    
    # Fetching the role ID of the admin making the request
    role_id = admin["role_id"]
    
    # Querying the database to get permissions associated with the admin's role
    permission = db.query(Permission).filter(Permission.role_id == role_id).all()
    
    # Extracting permission names from the query result
    permission_names = [permission.name for permission in permission]
    
    # Checking if the permission to update tenant status is granted to the admin
    if not "update_tenant_status" in permission_names:
        # If the permission is not found, raise an unauthorized exception
        raise HTTPException(status_code=401, detail="You are unauthorized to make this request")
    # fetch the tenant from the database
    user = db.query(TenantInfos).filter(TenantInfos.tenant_id == tenant_id).first()
    if user:
        if user.is_active:
            user.is_active = False
            db.commit()
            return {"message":"subscriber has been deactivated"}
        user.is_active = True
        db.commit()
        return {"message": "subscriber has been activated"}
    raise HTTPException(status_code=404, detail="tenant is not found")

# Endpoint for fetching admin data before updating
@router.get("/update_tenant/{tenant_id}/")
async def update_admin(tenant_id: int, admin: user_dependency, db: db_dependency):
    # Checking if admin is authenticated
    if admin is None:
        raise HTTPException(status_code=401, detail="Authentication failed")
    
    # Fetching the role ID of the admin making the request
    role_id = admin["role_id"]
    
    # Querying the database to get permissions associated with the admin's role
    permission = db.query(Permission).filter(Permission.role_id == role_id).all()
    
    # Extracting permission names from the query result
    permission_names = [permission.name for permission in permission]
    
    # Checking if the permission to update admin is granted to the admin
    if not "update_tenant_status" in permission_names:
        # If the permission is not found, raise an unauthorized exception
        raise HTTPException(status_code=401, detail="You are unauthorized to make this request")
    
    # Querying the database to check if the admin with the provided ID exists
    tenant = db.query(TenantInfos).filter(TenantInfos.tenant_id == tenant_id).all()
    
    # If admin not found, raise a not found exception
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    
    # Prepare response data
    tenant_data = []
    
    # Iterate through each admin and gather their information
    for tenant_info in tenant:
        tenant_dict = {
            "first_name": tenant_info.first_name,
            "last_name": tenant_info.last_name,
            "subdomain":tenant_info.subdomain,
            "registered_at":tenant_info.registered_at,
            "is_active": tenant_info.is_active,
            "credentials": []  # Initialize an empty list to store credentials
        }
        
        # Fetch credentials for the admin
        credential = tenant_info.credentials
        if credential:  # Check if credential exists
            tenant_dict["credentials"].append({
                "tenant_id": credential.id,
                "email": credential.email
            })
        
        # Append admin information to the response data
        tenant_data.append(tenant_dict)
    
    # Return the response containing admin data
    return {"admin": tenant_data}

# Endpoint for updating an admin
@router.put("/update_tenant/{tenant_id}/", status_code=status.HTTP_200_OK, tags=["admin"])
async def update_admin(tenant_info: TenantInfosSchema, tenant_id: int, admin: user_dependency, db: db_dependency):
    # Checking if admin is authenticated
    if admin is None:
        raise HTTPException(status_code=401, detail="Authentication failed")
    
    # Fetching the role ID of the admin making the request
    role_id = admin["role_id"]
    
    # Querying the database to get permissions associated with the admin's role
    permission = db.query(Permission).filter(Permission.role_id == role_id).all()
    
    # Extracting permission names from the query result
    permission_names = [permission.name for permission in permission]
    
    # Checking if the permission to update tenant is granted to the admin
    if not "update_tenant_status" in permission_names:
        # If the permission is not found, raise an unauthorized exception
        raise HTTPException(status_code=401, detail="You are unauthorized to make this request")
    
    # Querying the database to get the tenant with the provided ID
    tenant_data = db.query(TenantInfos).filter(TenantInfos.tenant_id == tenant_id).first()
    
    # If tenant not found, raise a not found exception
    if not tenant_data:
        raise HTTPException(status_code=404, detail="Admin not found")
    
    # Updating tenant information with the provided data
    tenant_data.first_name = tenant_info.first_name
    tenant_data.last_name = tenant_info.last_name
    tenant_data.subdomain = f"{tenant_info.subdomain}.yoursite.com"
    tenant_data.is_active = tenant_info.is_active
    
    # Committing to save changes to the database
    db.commit()
    
    # Returning a success message
    return {"message": "Tenant data has been updated"}