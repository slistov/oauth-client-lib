from ..config import get_oauth_callback_URL, get_api_host
from . import exceptions
from ..domain import model

from ..domain import commands
from ..service_layer import unit_of_work
from ..service_layer import messagebus

from typing import List
from urllib.parse import urlencode
import aiohttp
import requests


class OAuthProvider:
    def __init__(
        self,
        name,
        code_url=None,
        token_url=None,
        scopes=[],
        public_keys_url='',
        client_id='',
        client_secret=''
    ):
        self.name = name
        self.code_url = code_url
        self.token_url = token_url
        self.scopes = scopes
        self.public_keys_url = public_keys_url
        self.client_id = client_id
        self.client_secret = client_secret

    async def get_authorize_uri(self, uow=None):
        assert self.code_url
        uow = unit_of_work.SqlAlchemyUnitOfWork() if not uow else uow
        cmd = commands.CreateAuthorization("origin")
        [state_code] = await messagebus.handle(cmd, uow)
        return self._get_oauth_uri(state_code)

    async def request_token(self, grant) -> requests.Response:
        data = self._get_tokenRequest_data(grant=grant)
        self.response = await self._post(
            url=self.token_url,
            data=data
        )
        return self.response

    def _get_oauth_uri(self, state_code):
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": get_oauth_callback_URL(),
            "scope": self.scopes,
            "state": state_code
        }
        return f"{self.code_url}?{urlencode(params)}"

    def _get_tokenRequest_data(self, grant):
        if grant.grant_type == "authorization_code":
            data = {
                "code": grant.code,
                "redirect_uri": get_oauth_callback_URL()
            }
        elif grant.grant_type == "refresh_token":
            data = {"refresh_token": grant.code}
        else:
            raise exceptions.InvalidGrant(f"Unknown grant type {grant.grant_type} while requesting token")

        assert self.client_id
        assert self.client_secret
        data.update({
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": grant.grant_type
        })
        return data

    async def _post(self, url, data):
        return await post_async(
            url=url,
            data=data
        )

    def get_token(self) -> model.Token:
        return model.Token(self._get_token_str())

    def get_grant(self) -> model.Grant:
        return model.Grant("refresh_token", self._get_grant_code())

    def _get_token_str(self):
        return self.response.json().get("access_token", None)
        # return self.response

    def _get_grant_code(self):
        return self.response.json().get("refresh_token", None)
        # return self.response.get("refresh_token", None)


async def post_async(url, data):
    async with aiohttp.ClientSession() as session:
        response = await session.post(
            url=url,
            data=data
        )
        return response.json()
