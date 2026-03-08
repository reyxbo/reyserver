# !/usr/bin/env python
# -*- coding: utf-8 -*-

"""
@Time    : 2025-07-17
@Author  : Rey
@Contact : reyxbo@163.com
@Explain : Base methods.
"""

from typing import NoReturn
from http import HTTPStatus
from fastapi import HTTPException
from fastapi.params import Depends
from reykit.rbase import Base, Exit, throw

__all__ = (
    'ServerBase',
    'ServerExit',
    'ServerExitAPI',
    'exit_api',
    'depend_pass'
)

class ServerBase(Base):
    """
    Server base type.
    """

class ServerExit(ServerBase, Exit):
    """
    Server exit type.
    """

class ServerExitAPI(ServerExit, HTTPException):
    """
    Server exit API type.
    """

def exit_api(code: int = 400, text: str | None = None) -> NoReturn:
    """
    Throw exception to exit API.

    Parameters
    ----------
    code : Response status code.
    text : Explain text.
        `None`: Use Default text.
    """

    # Parameter.
    if not 400 <= code <= 499:
        throw(ValueError, code)
    if text is None:
        status = HTTPStatus(code)
        text = status.description

    # Throw exception.
    raise ServerExitAPI(code, text)

async def depend_pass_func() -> None:
    """
    Depend pass.
    """

depend_pass = Depends(depend_pass_func)
