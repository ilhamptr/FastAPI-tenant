"""Rename title column to name in project table

Revision ID: 7f29e30c661e
Revises: ede8000f6487
Create Date: 2024-04-13 08:39:13.643598

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '7f29e30c661e'
down_revision: Union[str, None] = 'ede8000f6487'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column('project', 'title', new_column_name='name')


def downgrade() -> None:
    pass
