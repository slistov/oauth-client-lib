# pylint: disable=redefined-outer-name
import time
import json
from pathlib import Path

import pytest
import requests
from requests.exceptions import ConnectionError
from sqlalchemy.exc import OperationalError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, clear_mappers

from oauth_client_lib.service_layer.oauth.provider import OAuthProvider
from src.oauth_client_lib.adapters.orm import mapper_registry, start_mappers
from oauth_client_lib.entrypoints import config
from src.oauth_client_lib.adapters import repository
from src.oauth_client_lib.service_layer import unit_of_work
from src.oauth_client_lib.domain import model
from src.oauth_client_lib.service_layer.unit_of_work import AbstractUnitOfWork

from src.oauth_client_lib.domain import model

from fastapi.testclient import TestClient
from oauth_client_lib import oauth_router
from oauth_client_lib.entrypoints.fastapi_app import app
from oauth_client_lib.entrypoints.routers.oauth import get_provider, get_uow


metadata = mapper_registry.metadata


@pytest.fixture
def in_memory_db():
    engine = create_engine("sqlite:///:memory:")
    metadata.create_all(engine)
    return engine


@pytest.fixture
def session_factory(in_memory_db):
    yield sessionmaker(bind=in_memory_db)


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
    url = config.get_api_host()
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
    (
        Path(__file__).parent / "../src/oauth_client_lib/entrypoints/fastapi_app.py"
    ).touch()
    time.sleep(0.5)
    wait_for_webapp_to_come_up()


class FakeOAuthProvider(OAuthProvider):
    """Фейковый сервис авторизации для тестирования

    Посылаем ему запросы, он должен что-нибудь ответить"""

    def __init__(
        self,
        code_url,
        scopes,
        token_url,
        userinfo_url,
        public_keys_url,
        client_id,
        client_secret,
        access_token="",
    ) -> None:
        self.endpoint = None
        self.data = None
        super().__init__(
            name="fake_provider",
            code_url=code_url,
            scopes=scopes,
            token_url=token_url,
            userinfo_url=userinfo_url,
            public_keys_url=public_keys_url,
            client_id=client_id,
            client_secret=client_secret,
        )

    async def _post(self, url, data):
        time.sleep(0.5)
        self.data = data
        self.response = requests.Response()
        self.response.status_code = 200
        json_content = {
            "access_token": f"test_access_token_for_grant_{data.get('code', data.get('refresh_token'))}",
            "refresh_token": "test_refresh_token",
            "scope": "test_scope",
            "token_type": "Bearer",
            "id_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgdXNlciIsImlhdCI6MTUxNjIzOTAyMn0.cLFHUVEN9rjbcABNFWuUI77w9VNC8HL4NVCYhbSwELk'",
        }
        self.response._content = json.dumps(json_content).encode("utf-8")
        return self.response.json()

    def _get_oauth_callback_URL(self):
        return "https://test-client/api/oauth/callback"


@pytest.fixture
def test_provider():
    return FakeOAuthProvider(
        code_url="https://accounts.test.com/o/oauth2/v2/auth",
        scopes=["https://www.testapis.com/auth/userinfo.email", "openid"],
        token_url="https://oauth2.testapis.com/token",
        userinfo_url="https://oauth2.testapis.com/userinfo",
        public_keys_url="https://www.testapis.com/oauth2/v3/certs",
        client_id="test_client_id",
        client_secret="test_client_secret",
    )


class FakeRepository(repository.AbstractRepository):
    def __init__(self, authorizations):
        super().__init__()
        self._authorizations = set(authorizations)

    def _add(self, authorization):
        self._authorizations.add(authorization)

    def _get_by_state(self, state):
        return next((a for a in self._authorizations if state == a.state.state), None)

    def _get_by_grant(self, code):
        return next(
            (
                a
                for a in self._authorizations
                for grant in a.grants
                if code == grant.code
            ),
            None,
        )

    def _get_by_token(self, access_token):
        return next(
            (
                a
                for a in self._authorizations
                for token in a.tokens
                if access_token == token.access_token
            ),
            None,
        )


class FakeUnitOfWork(unit_of_work.AbstractUnitOfWork):
    def __init__(self):
        self.authorizations = FakeRepository([])
        self.committed = False

    def _commit(self):
        self.committed = True

    def rollback(self):
        pass


@pytest.fixture
def uow():
    return FakeUnitOfWork()


app.include_router(oauth_router)


@pytest.fixture
def test_app(uow, test_provider):
    app.dependency_overrides[get_provider] = lambda: test_provider
    app.dependency_overrides[get_uow] = lambda: uow
    return app


@pytest.fixture(scope="function")
def client(test_app):
    return TestClient(test_app)


@pytest.fixture
def state() -> model.State:
    return model.State()


@pytest.fixture
def grant_authCode() -> model.Grant:
    return model.Grant(code="auth_code", grant_type="authorization_code")


@pytest.fixture
def grant_refresh() -> model.Grant:
    return model.Grant(code="refresh_code", grant_type="refresh_token")


@pytest.fixture
def token(grant_authCode):
    return model.Token(
        access_token=f"test_access_token_for_grant_{grant_authCode.code}",
        scope="test_scope",
        token_type="Bearer",
        id_token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgdXNlciIsImlhdCI6MTUxNjIzOTAyMn0.cLFHUVEN9rjbcABNFWuUI77w9VNC8HL4NVCYhbSwELk'",
    )


@pytest.fixture
def auth_wState(state):
    return model.Authorization(state=state)


@pytest.fixture
def auth_wStateGrant(state, grant_authCode):
    state.deactivate()
    return model.Authorization(state=state, grants=[grant_authCode])


@pytest.fixture
def auth_wStateGrantToken(state, grant_authCode, grant_refresh, token):
    state.deactivate()
    grant_authCode.deactivate()
    return model.Authorization(
        state=state, grants=[grant_authCode, grant_refresh], tokens=[token]
    )
