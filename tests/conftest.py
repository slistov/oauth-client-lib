# pylint: disable=redefined-outer-name
import time
from pathlib import Path

import pytest
import requests
from requests.exceptions import ConnectionError
from sqlalchemy.exc import OperationalError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, clear_mappers

from oauth_client_lib.service_layer.oauth_provider import OAuthProvider
from oauth_client_lib.adapters.orm import mapper_registry, start_mappers
from oauth_client_lib import config

metadata = mapper_registry.metadata


@pytest.fixture
def in_memory_db():
    engine = create_engine("sqlite:///:memory:")
    metadata.create_all(engine)
    return engine


@pytest.fixture
def session_factory(in_memory_db):
    start_mappers()
    yield sessionmaker(bind=in_memory_db)
    clear_mappers()


@pytest.fixture
def session(session_factory):
    return session_factory()


def wait_for_postgres_to_come_up(engine):
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            return engine.connect()
        except OperationalError:
            time.sleep(0.5)
    pytest.fail("Postgres never came up")


def wait_for_webapp_to_come_up():
    deadline = time.time() + 10
    url = config.get_api_url()
    while time.time() < deadline:
        try:
            return requests.get(url)
        except ConnectionError:
            time.sleep(0.5)
    pytest.fail("API never came up")


@pytest.fixture(scope="session")
def postgres_db():
    engine = create_engine(config.get_postgres_uri())
    wait_for_postgres_to_come_up(engine)
    metadata.create_all(engine)
    return engine


@pytest.fixture
def postgres_session_factory(postgres_db):
    start_mappers()
    yield sessionmaker(bind=postgres_db)
    clear_mappers()


@pytest.fixture
def postgres_session(postgres_session_factory):
    return postgres_session_factory()


@pytest.fixture
def restart_api():
    (Path(__file__).parent / "../src/oauth_client_lib/entrypoints/fastapi_app.py").touch()
    time.sleep(0.5)
    wait_for_webapp_to_come_up()


class FakeOAuthProvider(OAuthProvider):
    """Фейковый сервис авторизации для тестирования

    Посылаем ему запросы, он должен что-нибудь ответить"""
    def __init__(self) -> None:
        self.endpoint = None
        self.data = None

    def _post(self, endpoint, data):
        self.endpoint = endpoint
        self.data = data
        self.status_code = 200
        self.json_data = {
            "access_token": f"test_access_token_for_grant_{data.get('code', data.get('refresh_token'))}",
            "refresh_token": "test_refresh_token", 
        }
        time.sleep(0.5)
        # к токену добавить код гранта, чтобы токены отличать друг от друга
        # либо code, либо refresh_token - что есть, то и добавить
        return self
    

    @property
    def _url(self):
        return f"{self.service_url}{self.endpoint}"

@pytest.fixture
def fake_oauth_provider():
    return FakeOAuthProvider()

@pytest.fixture
def test_provider():
    return OAuthProvider(
            name='test_name',
            code_url='https://accounts.test.com/o/oauth2/v2/auth',
            scopes=[
                'https://www.testapis.com/auth/userinfo.email',
                'openid'
            ],
            token_url='https://oauth2.testapis.com/token',
            public_keys_url='https://www.testapis.com/oauth2/v3/certs'
        )
