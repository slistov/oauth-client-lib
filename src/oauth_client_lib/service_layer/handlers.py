"""Обработчики команд и событий

Команды и события генерируются в точках входа, см. /entrypoints
"""

from oauth_client_lib.domain import model, commands

from .unit_of_work import AbstractUnitOfWork
from . import exceptions
from .. import config
from . import oauth_provider


async def create_authorization(
    cmd: commands.CreateAuthorization,
    uow: AbstractUnitOfWork
) -> str:
    with uow:
        state = model.State()
        auth = model.Authorization(state=state)
        uow.authorizations.add(auth)
        uow.commit()
        return state.state


async def process_grant_recieved(
    cmd: commands.ProcessGrantRecieved,
    uow: AbstractUnitOfWork
):
    """Обработчик команды Обработать код авторизации
    """
    with uow:
        auth = uow.authorizations.get_by_state_code(cmd.state_code)
        if auth is None or not auth.is_active:
            raise exceptions.InvalidState("No active authorization found")

        if cmd.type == "authorization_code" and cmd.state_code:
            # Exception: are we under attack?
            if not auth.state.is_active:
                # if we are, then invoke authorization
                auth.deactivate()
                uow.commit()
                raise exceptions.InactiveState("State is inactive")
            auth.state.deactivate()

        grant = model.Grant(grant_type=cmd.type, code=cmd.code)
        auth.grants.append(grant)
        uow.commit()


async def request_token(
    cmd: commands.RequestToken,
    uow: AbstractUnitOfWork
):
    with uow:
        auth = uow.authorizations.get_by_grant_code(cmd.grant_code)
        if auth is None or not auth.is_active:
            raise exceptions.InvalidGrant("No active authorization found")

        old_grant = auth.get_grant_by_code(cmd.grant_code)
        if not old_grant or not old_grant.is_active:
            raise exceptions.InvalidGrant(
                "No grant found for token requesting"
            )
        old_grant.deactivate()

        old_token = auth.get_active_token()
        if old_token:
            old_token.deactivate()

        oauth = cmd.oauth
        if not oauth:
            scopes, urls = config.get_oauth_params(auth.provider_name)
            oauth = oauth_provider.OAuthProvider(
                scopes=scopes,
                code_url=urls['code'],
                token_url=urls['token'],
                public_keys_url=urls['keys']
            )
        await oauth.request_token(grant=old_grant)
        new_token = oauth.get_token()
        new_grant = oauth.get_grant()
        auth.tokens.append(new_token)
        auth.grants.append(new_grant)
        uow.commit()
        return new_token
