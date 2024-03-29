"""model Authorization - agregate - all orm tables

Revision ID: addbb5103971
Revises: 1ef77c18afb9
Create Date: 2022-09-28 18:25:21.463509

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'addbb5103971'
down_revision = '1ef77c18afb9'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('authorizations',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('created', sa.DateTime(), nullable=True),
    sa.Column('is_active', sa.Boolean(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('grants',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('auth_id', sa.Integer(), nullable=True),
    sa.Column('code', sa.String(), nullable=True),
    sa.Column('created', sa.DateTime(), nullable=True),
    sa.Column('is_active', sa.Boolean(), nullable=True),
    sa.ForeignKeyConstraint(['auth_id'], ['authorizations.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('tokens',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('auth_id', sa.Integer(), nullable=True),
    sa.Column('access_token', sa.String(), nullable=True),
    sa.Column('created', sa.DateTime(), nullable=True),
    sa.Column('expires_in', sa.Interval, nullable=True),
    sa.Column('scope', sa.String(), nullable=True),
    sa.Column('token_type', sa.String(), nullable=True),
    sa.Column('is_active', sa.Boolean(), nullable=True),
    sa.ForeignKeyConstraint(['auth_id'], ['authorizations.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.add_column('states', sa.Column('auth_id', sa.Integer(), nullable=True))
    op.create_foreign_key(None, 'states', 'authorizations', ['auth_id'], ['id'])
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'states', type_='foreignkey')
    op.drop_column('states', 'auth_id')
    op.drop_table('tokens')
    op.drop_table('grants')
    op.drop_table('authorizations')
    # ### end Alembic commands ###
