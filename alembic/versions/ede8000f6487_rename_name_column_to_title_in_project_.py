"""Rename name column to title in project table

Revision ID: ede8000f6487
Revises: bf5ccae85ce9
Create Date: 2024-04-12 21:39:08.300068

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'ede8000f6487'
down_revision: Union[str, None] = 'bf5ccae85ce9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column('project', 'name', new_column_name='title')

def downgrade() -> None:
    pass
