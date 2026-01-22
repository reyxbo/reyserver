# !/usr/bin/env python
# -*- coding: utf-8 -*-

"""
@Time    : 2025-10-21
@Author  : Rey
@Contact : reyxbo@163.com
@Explain : Redirect methods.
"""


from fastapi import APIRouter
from fastapi.responses import RedirectResponse
from reykit.rnet import join_url

from .rbind import Bind


__all__ = (
    'router_redirect',
)


router_redirect = APIRouter()


@router_redirect.get('/{path:path}')
async def redirect_all(
    path: str = Bind.i.path,
    server: Bind.Server = Bind.server
) -> RedirectResponse:
    """
    Redirect all requests to the target server.

    Parameters
    ----------
    path : Resource path.

    Returns
    -------
    Redirect response.
    """

    # Response.
    url = join_url(server.api_redirect_server_url, path)
    response = RedirectResponse(url, 308)

    return response
