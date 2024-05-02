from sqlalchemy import Boolean, Column, Integer, String,DateTime
from sqlalchemy.orm import relationship
from database import Base

from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship

class OTP(Base):
    __tablename__ = "otp"

    id = Column(Integer, primary_key=True, autoincrement=True)
    owner = Column(String, index=True)
    otp = Column(String,index=True)
    expiration = Column(DateTime,index=True)
    
