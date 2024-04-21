from datetime import datetime
from pydantic import BaseModel, validator

class AdminsSchema(BaseModel):
    id: int
    first_name: str
    last_name: str
    email: str
    is_active: bool