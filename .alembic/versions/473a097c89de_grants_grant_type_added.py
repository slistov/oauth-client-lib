"""Grants: grant_type added

Revision ID: 473a097c89de
Revises: addbb5103971
Create Date: 2022-10-14 10:04:21.243860

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '473a097c89de'
down_revision = 'addbb5103971'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('grants', sa.Column('grant_type', sa.String(), nullable=True))
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('grants', 'grant_type')
    # ### end Alembic commands ###
