from fastapi import FastAPI, Depends
from urllib.parse import urlencode

from ..domain import commands
from ..service_layer import unit_of_work
from ..service_layer import messagebus

from ..adapters import orm
from ..config import config

from . import schemas

app = FastAPI()
orm.start_mappers()


def get_oauth_uri(state_code):
    client_id, _ = config.get_client_credentials()

    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": config.get_oauth_callback_URL(),
        "scope": config.get_scope(),
        "state": state_code
    }
    return f"{config.get_oauth_host()}?{urlencode(params)}"


@app.get('/api/oauth/authorize')
async def get_oauth_authorize_uri():
    uow = unit_of_work.SqlAlchemyUnitOfWork()
    cmd = commands.CreateAuthorization("origin")
    [state_code] = messagebus.handle(cmd, uow)
    return get_oauth_uri(state_code)


@app.get('/api/oauth/callback')
async def get_oauth_callback_uri(params: schemas.callback_query = Depends()):
    uow = unit_of_work.SqlAlchemyUnitOfWork()
    actions_todo = [
        commands.ProcessGrantRecieved(
            params.state,
            "authorization_code",
            params.code
        ),
        commands.RequestToken(params.code)
    ]
    for msg in actions_todo:
        messagebus.handle(msg, uow)
    return 200
