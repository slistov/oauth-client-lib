import pytest
import requests
from urllib.parse import urlparse, parse_qsl
from urllib.parse import urlencode

from src.oauth_client_lib import config


# @pytest.mark.usefixtures("postgres_db")
@pytest.mark.usefixtures("in_memory_db")
@pytest.mark.usefixtures("restart_api")
def test_happy_path_returns_200_and_redirect_uri_line():
    client_id, _ = config.get_client_credentials()

    url = f"{config.get_api_host()}{config.get_api_authorize_uri()}"
    r = requests.get(f"{url}")

    assert r.status_code == 200

    parsed_url = urlparse(r.text)
    params = dict(parse_qsl(parsed_url.query))
    assert params.items() >= {
        'response_type': 'code',
        'client_id': client_id,
        'redirect_uri': config.get_oauth_callback_URL(),
        'scope': config.get_scope(),
        # 'state': 'some_code"'
    }.items()

# '"http://localhost:9000/docs?response_type=code&client_id=529d76e8-0b47-4e33-b2ef-97621cc5a53e&redirect_uri=http%3A%2F%2Flocalhost%3A9000%2Fapi%2Foauth%2Fcallback&scope=username+email&state=some_code"'


# @pytest.mark.usefixtures("postgres_db")
@pytest.mark.usefixtures("in_memory_db")
@pytest.mark.usefixtures("restart_api")
def test_unhappy_path_callback_raises_403_if_state_not_found():
    callback_url = config.get_oauth_callback_URL()
    query_params = urlencode({"code": "test_code", "state": "__test_state"})
    url = f"{callback_url}?{query_params}"
    r = requests.get(url)

    assert r.status_code == 403
    assert r.text == '{"detail":{"error":"state_error","description":"No active authorization found"}}'


# def test_unhappy_path_recieves_authCodeGrant_then_requestsTokenFromOAuth_then_redirectsToWhereUserCameFrom():
