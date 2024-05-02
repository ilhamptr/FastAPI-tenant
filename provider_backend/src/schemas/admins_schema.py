from pydantic import BaseModel


class Status(BaseModel):
    username:str
    
class Email(BaseModel):
    email:str
    
    
class AdminRegistration(BaseModel):
    emai:str
    password:str

# Define your custom Pydantic model for form data
class CustomOAuth2PasswordRequestForm(BaseModel):
    username: str
    password: str
    otp: str  # Add OTP field