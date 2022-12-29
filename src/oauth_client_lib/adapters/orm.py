from sqlalchemy import (
    Table,
    Column,
    Integer,
    String,
    DateTime,
    Interval,
    Boolean,
    ForeignKey,
    FetchedValue
)

from ..domain import model
from sqlalchemy import event

from sqlalchemy.orm import registry, relationship

mapper_registry = registry()

users = Table(
    'users', mapper_registry.metadata,
    Column(
        'id',
        Integer,
        primary_key=True,
        autoincrement=True,
        server_default=FetchedValue()
    ),
    Column('email', String),
    Column('username', String),
    Column('created', DateTime),
    Column('is_active', Boolean)
)

authorizations = Table(
    'authorizations', mapper_registry.metadata,
    Column('id', Integer, primary_key=True, autoincrement=True),
    Column('provider_name', String),
    Column('created', DateTime),
    Column('is_active', Boolean),
)

states = Table(
    'states', mapper_registry.metadata,
    Column('id', Integer, primary_key=True, autoincrement=True),
    Column('auth_id', ForeignKey("authorizations.id")),
    Column('code', String),
    Column('created', DateTime),
    Column('is_active', Boolean),
)

grants = Table(
    'grants', mapper_registry.metadata,
    Column('id', Integer, primary_key=True, autoincrement=True),
    Column('auth_id', ForeignKey("authorizations.id")),
    Column('grant_type', String),
    Column('code', String),
    Column('created', DateTime),
    Column('is_active', Boolean),
)

tokens = Table(
    'tokens', mapper_registry.metadata,
    Column('id', Integer, primary_key=True, autoincrement=True),
    Column('auth_id', ForeignKey("authorizations.id")),
    Column('access_token', String),
    Column('created', DateTime),
    Column('expires_in', Interval),
    Column('is_active', Boolean),
)


def start_mappers():
    mapper_registry.map_imperatively(model.User, users)
    states_mapper = mapper_registry.map_imperatively(model.State, states)
    grants_mapper = mapper_registry.map_imperatively(model.Grant, grants)
    tokens_mapper = mapper_registry.map_imperatively(model.Token, tokens)
    mapper_registry.map_imperatively(
        model.Authorization,
        authorizations,
        properties={
            "state": relationship(states_mapper, uselist=False),
            "grants": relationship(grants_mapper),
            "tokens": relationship(tokens_mapper)
        }
    )


@event.listens_for(model.Authorization, "load")
def receive_load(auth, _):
    auth.events = []
