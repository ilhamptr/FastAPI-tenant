from pydantic import BaseModel


class Status(BaseModel):
    username:str
    
class Email(BaseModel):
    email:str
    
    
class AdminRegistration(BaseModel):
    email:str
    password:str
    
class OTPVerification(BaseModel):
    email:str
    otp:str
    
class CreateAdmin(BaseModel):
    email:str
    password:str
    role_name:str
