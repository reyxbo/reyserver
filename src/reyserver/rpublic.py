# !/usr/bin/env python
# -*- coding: utf-8 -*-

"""
@Time    : 2025-10-21
@Author  : Rey
@Contact : reyxbo@163.com
@Explain : Public methods.
"""


from fastapi import APIRouter
from fastapi.responses import HTMLResponse, FileResponse
from reykit.ros import File, Folder

from .rbind import Bind


__all__ = (
    'router_public',
)


router_public = APIRouter()


@router_public.get('/')
async def home(server: Bind.Server = Bind.server) -> HTMLResponse:
    """
    Home page.

    Parameters
    ----------
    Home page HTML content.
    """

    # Parameter.
    public_dir = server.api_public_dir
    file_path = Folder(public_dir) + 'index.html'
    file = File(file_path)

    # Response.
    response = HTMLResponse(file.str)

    return response


@router_public.get('/public/{path:path}')
async def download_public_file(path: str = Bind.i.path) -> FileResponse:
    """
    Download public file.

    Parameters
    ----------
    path : Relative path of based on public directory.

    Returns
    -------
    File.
    """

    pass
