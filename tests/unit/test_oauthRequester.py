from auth_client.service_layer.oauth_requester import OAuthRequester
from ..conftest import FakeOAuthService

class TestOAuthRequest:
    def test_oauthRequester_sends_request(self):
        fake_oauth_service = FakeOAuthService("http://fake.oauth.service/api")
        oauth = OAuthRequester(fake_oauth_service)
        
        data = {"param1": "value1", "param2": "value2"}
        results = oauth.post(endpoint="/token", data=data)

        assert fake_oauth_service.url == "http://fake.oauth.service/api/token"
        assert fake_oauth_service.data == data

    def test_oauthRequester_recieves_response_from_oauth(self):
        fake_oauth_service = FakeOAuthService("http://fake.oauth.service/api")
        oauth = OAuthRequester(fake_oauth_service)
        
        data = {"param1": "value1", "param2": "value2"}
        results = oauth.post(endpoint="/token", data=data)

        assert results == {"k1": "v1", "k2": "v2"}
        