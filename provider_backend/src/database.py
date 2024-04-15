# Ref. https://fastapi.tiangolo.com/tutorial/sql-databases/

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from src.config import Settings

# Import a database URL for SQLAlchemy from the environment variable DATABASE_URL
settings = Settings()
SQLALCHEMY_DATABASE_URL = settings.PROVIDER_DATABASE_URL

# Create the SQLAlchemy engine
engine = create_engine(SQLALCHEMY_DATABASE_URL)
#engine = create_engine("postgresql://reqsUser:reqsUserPasswd@localhost:5432/reqsDB")

# Create a SessionLocal class
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create a Base class
Base = declarative_base()

