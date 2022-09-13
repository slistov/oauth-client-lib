# pylint: disable=too-few-public-methods
from datetime import date
from typing import Optional
from dataclasses import dataclass


class Command:
    pass


@dataclass
class CreateState(Command):
    pass


@dataclass
class ValidateState(Command):
    code: str

# @dataclass
# class CreateBatch(Command):
#     ref: str
#     sku: str
#     qty: int
#     eta: Optional[date] = None


# @dataclass
# class ChangeBatchQuantity(Command):
#     ref: str
#     qty: int
