# Create initial Pydantic models / schemas

from datetime import datetime
from pydantic import BaseModel, validator

class ProjectSchema(BaseModel):
    id: int
    first_name: str
    last_name: str
    email: str
    subdomain: str
    registred_at: datetime
    is_active: bool

    '''
    @validator('icon')
    def validate_icon(cls, v):
        if v:
            # Check image type
            allowed_formats = ['png', 'jpg', 'jpeg']
            if v.content_type not in allowed_formats:
                raise ValueError(f'Invalid image format. Allowed formats: {", ".join(allowed_formats)}')
            
            # Vérifier la taille de l'image
            max_size_bytes = 2 * 1024 * 1024  # 2 MB
            if v.size > max_size_bytes:
                raise ValueError(f'Image size exceeds maximum allowed size of {max_size_bytes} bytes')
            
        return v
    '''

