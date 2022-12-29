"""Паттерн Репозиторий

Абстракция над хранилищем"""

import abc
from . import orm
from ..domain import model


class AbstractRepository(abc.ABC):
    """Абстрактный репозиторий
    """
    def __init__(self):
        self.seen = set()

    def add(self, auth: model.Authorization) -> model.Authorization:
        self._add(auth)
        self.seen.add(auth)

    def get_by_state_code(self, state_code) -> model.Authorization:
        auth = self._get_by_state(state_code)
        if auth:
            self.seen.add(auth)
        return auth

    def get_by_grant_code(self, code) -> model.Authorization:
        auth = self._get_by_grant_code(code)
        if auth:
            self.seen.add(auth)
        return auth

    def get_by_token(self, token) -> model.Authorization:
        auth = self._get_by_token(token)
        if auth:
            self.seen.add(auth)
        return auth

    @abc.abstractmethod
    def _add(self, auth: model.Authorization):
        raise NotImplementedError

    @abc.abstractmethod
    def _get_by_state(self, code) -> model.Authorization:
        raise NotImplementedError

    @abc.abstractmethod
    def _get_by_grant_code(self, code) -> model.Authorization:
        raise NotImplementedError

    @abc.abstractmethod
    def _get_by_token(self, token) -> model.Authorization:
        raise NotImplementedError


class SQLAlchemyRepository(AbstractRepository):
    def __init__(self, session):
        super().__init__()
        self.session = session

    def _add(self, auth: model.Authorization):
        self.session.add(auth)

    def _get_by_state(self, code) -> model.Authorization:
        return (
            self.session.query(model.Authorization)
            .join(model.State)
            .filter(orm.states.c.code == code)
            .first()
        )

    def _get_by_grant_code(self, code) -> model.Authorization:
        return (
            self.session.query(model.Authorization)
            .join(model.Grant)
            .filter(orm.grants.c.code == code)
            .first()
        )

    def _get_by_token(self, token) -> model.Authorization:
        return (
            self.session.query(model.Authorization)
            .join(model.Token)
            .filter(orm.tokens.c.token == token)
            .first()
        )

    def cancel_authorization(self):
        return (
            self.session.query(model.Authorization).
            join(model.State)
        )
