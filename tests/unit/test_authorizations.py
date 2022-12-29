from src.oauth_client_lib.domain import model


def create_auth_data():
    state = model.State("test_state")
    grant = model.Grant("authorization_code", "test_code")
    token = model.Token("test_token")
    auth = model.Authorization(state, [grant], [token])
    return state, grant, token, auth


def test_when_authorization_deactivates_it_also_deactivates_its_state_grants_and_tokens():
    state, grant, token, auth = create_auth_data()

    assert state.is_active
    assert grant.is_active
    assert token.is_active

    auth.deactivate()

    assert not auth.is_active
    assert not state.is_active
    assert not grant.is_active
    assert not token.is_active


# def test_token_request_adds_token_and_grant(fake_token_requester):
#     state, grant, token, auth = create_auth_data()

#     assert len(auth.grants) == 1
#     assert len(auth.tokens) == 1    

#     auth.request_token(fake_token_requester)

#     assert len(auth.grants) == 2
#     assert len(auth.tokens) == 2


# def test_token_request_deactivates_old_grant_and_token(fake_token_requester):
#     state, grant, token, auth = create_auth_data()

#     assert grant.is_active
#     assert token.is_active

#     auth.request_token(fake_token_requester)

#     assert not grant.is_active
#     assert not token.is_active
