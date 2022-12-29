from src.oauth_client_lib.service_layer import unit_of_work
from src.oauth_client_lib.domain import model
from datetime import datetime

def insert_authorization(session, id, created=datetime.utcnow(), is_active=True):
    session.execute(
        "INSERT INTO authorizations (id, created, is_active) VALUES (:id, :created, :is_active)",
        dict(id=id, created=created, is_active=is_active),
    )


def insert_state(session, auth_id, code, created=datetime.utcnow(), is_active=True):
    session.execute(
        "INSERT INTO states (auth_id, code, created, is_active) VALUES (:auth_id, :code, :created, :is_active)",
        dict(auth_id=auth_id, code=code, created=created, is_active=is_active),
    )


def test_uow_can_retrieve_an_authorization(session_factory):
    session = session_factory()
    insert_authorization(session, id=1)
    insert_state(session, auth_id=1, code="test_state_code")
    session.commit()

    uow = unit_of_work.SqlAlchemyUnitOfWork(session_factory)
    with uow:
        auth = uow.authorizations.get_by_state_code("test_state_code")
        code = auth.state.code
        uow.commit()

    assert code == "test_state_code"


def test_rolls_back_uncommitted_work_by_default(session_factory):
    uow = unit_of_work.SqlAlchemyUnitOfWork(session_factory)
    with uow:
        insert_authorization(uow.session, id=1)

    new_session = session_factory()
    rows = list(new_session.execute('SELECT * FROM "authorizations"'))
    assert rows == []
