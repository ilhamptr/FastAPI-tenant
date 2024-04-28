from pydantic import BaseModel

class Status(BaseModel):
    username:str
    
class Email(BaseModel):
    email:str