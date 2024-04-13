# Create initial Pydantic models / schemas

from pydantic import BaseModel

class ProjectSchema(BaseModel):
    id: int
    name: str
    key: str
    description: str | None = None