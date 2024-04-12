# Project files structure
* Ref. https://fastapi.tiangolo.com/tutorial/bigger-applications/?h=files+structure

project
|   ├── app                  # Root package
|   │   ├── __init__.py      # Makes "app" a Python package
|   │   ├── main.py          # Entry point
|   │   ├── dependencies.py  # Dependencies used in several places of the app
|   │   ├── routers          # Subpackage with route definitions
|   │   │   ├── __init__.py  # Makes "routers" a Python subpackage
|   │   │   ├── items.py     # Module with route for item-related functionalities
|   │   │   └── users.py     # Module with route for user-related functionalities
|   │   ├── models           # Subpackage with data models (e.g., SQLAlchemy models)
|   │   │   ├── __init__.py  # Makes "models" a Python subpackage
|   │   │   ├── item.py      # Module with Item data model
|   │   │   └── user.py      # Module with User data model
|   │   ├── schemas          # Subpackage with Pydantic models
|   │   │   ├── __init__.py  # Makes "schemas" a Python subpackage
|   │   │   ├── item.py      # Module with Item Pydantic model
|   │   │   └── user.py      # Module with User Pydantic model
|   │   ├── internal         # Subpackage with code not directly exposed to the API
|   │   │   ├── __init__.py  # Makes "internal" a Python subpackage
|   │   │   └── admin.py     # Module with administrative functionalities
|   │   └── config.py        # Module with configuration
├── tests                    # Package with your application's unit tests
│   ├── __init__.py          # Makes "tests" a Python package
│   ├── test_items.py        # Module with unit tests for item-related functionalities
│   └── test_users.py        # Module with unit tests for user-related functionalities
├── .env                     # File with environment variables

* The dependencies.py module is used to define reusable dependencies that can be injected into route handlers or other parts of our application using FastAPI's dependency injection system. Dependencies are typically used to perform tasks such as :
- database connections, 
- authentication, authorization, 
- rate limiting, and more,

* The internal folder contains code that is specific to your application and doesn't make sense outside of it. Here are some examples:
- Authentication and authorization functions,
- Email or notification sending functions,
- Image or file processing functions,
- Data validation or cleaning functions,
- Utility classes or modules for database management, caching, logging, etc.

# Packages
- Install requirement.txt (or use docker generated file ... see section 
  'docker')

# Run server
- ~/myproject/app$ uvicorn main:app --reload
- ~/myproject$ uvicorn src.main:app --reload (if main inside [src])

# Set up DB
- https://fastapi.tiangolo.com/how-to/async-sql-encode-databases/?h=sqlalchemy#import-and-set-up-sqlalchemy

# Migration
- Ref. https://alembic.sqlalchemy.org/en/latest/tutorial.html#the-migration-environment
- Install 'alembic" using requirement.txt
- ~/myproject$ uvicorn src.main:app --reload
  System creates our models [allTables]
- Initialise and create migration alembic repo:
  ~/myproject/alembic init alembic
- Need to modify [env.py]
- Create a 1st revision:
  ~/myproject$ alembic revision -m "1st_revision"
  In our db, it will create [alembic_version] table
- upgrade the database with the latest alembic migration:
  Suppose we change in our [models] and [schemas]  
  ~/myproject/alembic revision -m "Rename name column to title in project table"
- Edit the generated migartion file by renaming column:
  """
  def upgrade() -> None:
      op.alter_column('projet', 'name', new_column_name='title')
  """
- Execute our 1st migration on db: ~/myproject$ alembic upgrade head
- Execute our 2nd migration on db: ~/myproject$ alembic revision -m "Add a column"

- Running again to head: ~/myproject$ alembic upgrade head

# Troubleshooting Alembic
- Ref. https://medium.com/@johannes.ocean/the-troubles-i-ran-into-while-setting-up-database-migrations-f5ec08d94da1

# Docker
- Visual Studio Code: instal [ms-azuretools.vscode-docker]
- Create [Dockerfile] using visualCode
- ~/myproject$ pip freeze > requirements.txt
  it will create all the packages with dependencies in the current virtual environment
