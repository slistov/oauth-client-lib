"""Агрегат для бизнес-процесса получения токена

Получить state

Получить код авторизации
- валидировать state
- деактивировать state
- принять код, связав его со state
"""

from typing import List

from .state import State
from .grant import Grant
from .access_token import Token
from .user import User


class Authorization:
    def __init__(
        self,
        state: State = State(),
        grants: List[Grant] = None,
        tokens: List[Token] = None,
        user: User = None,
        is_active: bool = True,
        provider_name: str = 'Own'
    ):
        self.state = state
        self.provider_name = provider_name
        self.grants = grants if grants else []
        self.tokens = tokens if tokens else []
        self.user = user if user else None
        self.is_active = is_active
        self.events = []

    def get_grant_by_code(self, code: str):
        return next(grant for grant in self.grants if grant.code == code)

    def get_active_grant(self):
        return next(grant for grant in self.grants if grant.is_active)

    def get_active_token(self):
        try:
            return next(token for token in self.tokens if token.is_valid)
        except Exception:
            return None

    def deactivate(self):
        self.is_active = False
        self._deactivate_state()
        self._deactivate_grants()
        self._deactivate_tokens()

    def _deactivate_state(self):
        self.state.deactivate()

    def _deactivate_grants(self):
        for grant in [grant for grant in self.grants if grant.is_active]:
            grant.deactivate()

    def _deactivate_tokens(self):
        for token in [token for token in self.tokens if token.is_active]:
            token.deactivate()
