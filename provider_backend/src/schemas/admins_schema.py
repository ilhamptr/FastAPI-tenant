from pydantic import BaseModel
from typing import Optional

class Status(BaseModel):
    subdomain:str
    
class Email(BaseModel):
    email:str
    
    
class AdminRegistration(BaseModel):
    email:str
    password:str
    
class OTPVerification(BaseModel):
    otp:str
    
class CreateAdmin(BaseModel):
    email:str
    password:str
    role_name:str
    
class AdminInfosSchema(BaseModel):
    first_name: str
    last_name: str
    is_active: Optional[bool]

