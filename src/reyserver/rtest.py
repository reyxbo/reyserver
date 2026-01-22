# !/usr/bin/env python
# -*- coding: utf-8 -*-

"""
@Time    : 2025-10-21
@Author  : Rey
@Contact : reyxbo@163.com
@Explain : Test methods.
"""


from typing import Literal
from fastapi import APIRouter
from reykit.rtask import async_sleep

from .rbind import Bind


__all__ = (
    'router_test',
)


router_test = APIRouter()


@router_test.get('/test')
def test() -> Literal['test']:
    """
    Test.

    Returns
    -------
    Text `test`.
    """

    # Resposne.
    response = 'test'

    return response


@router_test.post('/test/echo')
def test_echo(data: dict = Bind.i.body) -> dict:
    """
    Echo test.

    Paremeters
    ----------
    data : Echo data.

    Returns
    -------
    Echo data.
    """

    return data


@router_test.get('/test/wait')
def test_wait(second: float = Bind.Query(1, gt=0, le=10)) -> Literal['test']:
    """
    Wait test.

    Paremeters
    ----------
    second : Wait seconds, range is `(0-10]`.

    Returns
    -------
    Text `test`.
    """

    # Sleep.
    async_sleep(second)

    # Resposne.
    response = 'test'

    return response
