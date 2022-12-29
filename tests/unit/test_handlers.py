# pylint: disable=no-self-use
import pytest
from src.oauth_client_lib.domain import commands
from src.oauth_client_lib.service_layer import (
    messagebus,
    exceptions
)

from src.oauth_client_lib.domain import model


class TestAuthorization:
    @pytest.mark.asyncio
    async def test_authorization_is_created_and_could_be_found_by_stateCode(self, uow):
        """Содать авторизацию
        После создания авторизации, её можно получить по state-коду"""
        [state_code] = await messagebus.handle(
            commands.CreateAuthorization("source_url"),
            uow
        )
        assert uow.authorizations.get_by_state_code(state_code) is not None
        assert uow.committed

    @pytest.mark.asyncio
    async def test_state_becomes_inactive_after_AuthCodeGrant_processed(self, uow):
        """Деактивировать state после получения кода авторизации
        Сервис авторизации отдаёт нам код авторизации и прилагает код state.
        Код state необходимо деактивировать"""
        [state_code] = await messagebus.handle(
            commands.CreateAuthorization("source_url"),
            uow
        )
        await messagebus.handle(
            commands.ProcessGrantRecieved(
                state_code,
                "authorization_code",
                "test_code"
            ),
            uow
        )
        auth = uow.authorizations.get_by_state_code(state_code)
        assert not auth.state.is_active


class TestGrant:
    """Обработать полученный код авторизации

    С кодом авторизации приходит state - в зависимости от его валидации
    либо принимаем код авторизации, либо отвергаем операцию"""
    @pytest.mark.asyncio
    async def test_process_grant_then_get_auth_by_grant(self, uow):
        [state_code] = await messagebus.handle(
            commands.CreateAuthorization("source_url"),
            uow
        )
        await messagebus.handle(
            commands.ProcessGrantRecieved(
                state_code,
                "authorization_code",
                "test_code"
            ),
            uow
        )
        assert uow.authorizations.get_by_grant_code("test_code") is not None
        assert uow.authorizations.get_by_grant_code("test_code").is_active
        assert uow.committed

    @pytest.mark.asyncio
    async def test_grant_with_wrong_stateCode_raises_InvalidState_exception(self, uow):
        [auth] = await messagebus.handle(commands.CreateAuthorization("source_url"), uow)

        with pytest.raises(exceptions.InvalidState, match="No active authorization found"):
            await messagebus.handle(commands.ProcessGrantRecieved("wrong_state_code", "authorization_code", "test_code"), uow)

    @pytest.mark.asyncio
    async def test_grant_with_inactive_stateCode_raises_INACTIVEState_exception(self, uow):
        [state_code] = await messagebus.handle(commands.CreateAuthorization("source_url"), uow)
        auth = uow.authorizations.get_by_state_code(state_code)
        auth.state.deactivate()

        with pytest.raises(exceptions.InactiveState, match="State is inactive"):
            await messagebus.handle(commands.ProcessGrantRecieved(
                    auth.state.state,
                    "authorization_code",
                    "test_code"
                ),
                uow
            )


class TestAccessToken:
    @pytest.mark.asyncio
    async def test_for_existing_authorization_by_access_token(self, uow):
        [state_code] = await messagebus.handle(commands.CreateAuthorization("source_url"), uow)
        await messagebus.handle(commands.ProcessGrantRecieved(state_code, "authorization_code", "test_code"), uow)
        auth = uow.authorizations.get_by_state_code(state_code)
        auth.tokens.append(model.Token("test_token"))

        assert uow.authorizations.get_by_token("test_token") is not None
        assert uow.committed

    @pytest.mark.asyncio
    async def test_get_active_token_for_existing_authorization(self, uow):
        [state_code] = await messagebus.handle(commands.CreateAuthorization("source_url"), uow)
        await messagebus.handle(commands.ProcessGrantRecieved(state_code, "authorization_code", "test_code"), uow)
        auth = uow.authorizations.get_by_state_code(state_code)
        auth.tokens.append(model.Token("test_token"))

        assert auth.get_active_token().access_token == "test_token"
        assert uow.committed


class TestAttackHandling:
    @pytest.mark.asyncio
    async def test_for_existing_authorization_inactive_STATECode_deactivates_authorization_completely(self, uow):
        [state_code] = await messagebus.handle(commands.CreateAuthorization("source_url"), uow)
        auth = uow.authorizations.get_by_state_code(state_code)
        grant = model.Grant("authorization_code", "test_code")
        auth.grants.append(grant)

        token = model.Token(access_token="test_token", expires_in=3600)
        auth.tokens.append(token)

        assert auth.is_active
        assert auth.state.is_active
        assert grant.is_active
        assert token.is_active

        auth.state.deactivate()
        with pytest.raises(exceptions.InactiveState, match="State is inactive"):
            await messagebus.handle(commands.ProcessGrantRecieved(auth.state.state, "authorization_code", "test_code"), uow)

        assert not auth.is_active
        assert not auth.state.is_active
        assert not grant.is_active
        assert not token.is_active


class TestTokenRequest:
    @pytest.mark.asyncio
    async def test_tokenRequester_runs_token_request(self, test_provider, uow):
        """Убедиться, что при запросе токена что-то приходит в ответ"""
        auth = model.Authorization(
            grants=[model.Grant("authorization_code", "test_code")]
        )
        uow.authorizations.add(auth)
        do_request_token = commands.RequestToken("test_code", test_provider)
        await messagebus.handle(do_request_token, uow)
        token = auth.get_active_token()
        assert token.access_token == 'test_access_token_for_grant_test_code'

    @pytest.mark.asyncio
    async def test_several_tokenRequests_return_different_tokens(self, test_provider, uow):
        """Проверить, что при каждом новом запросе токена,
        приходит другой токен.

        То есть нет одинаковых токенов"""
        auth = model.Authorization(
            grants=[
                model.Grant("authorization_code", "test_code1"),
                model.Grant("refresh_token", "test_code2"),
            ]
        )
        uow.authorizations.add(auth)
        [token1] = await messagebus.handle(commands.RequestToken("test_code1", test_provider), uow)
        [token2] = await messagebus.handle(commands.RequestToken("test_code2", test_provider), uow)
        assert not token1.access_token == token2.access_token

    @pytest.mark.asyncio
    async def test_tokenRequest_deactivates_old_token_and_old_grant(self, test_provider, uow):
        """Проверить, что после запроса нового токена
        и гранта (токена обновления),
        старые токен и грант деактивированы"""
        grant = model.Grant("refresh_token", "test_code")
        token = model.Token("test_access_token")
        auth = model.Authorization(grants=[grant], tokens=[token])
        uow.authorizations.add(auth)

        assert grant.is_active
        assert token.is_active
        [access_token] = await messagebus.handle(
            commands.RequestToken("test_code", test_provider),
            uow
        )
        assert not grant.is_active
        assert not token.is_active
