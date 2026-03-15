# !/usr/bin/env python
# -*- coding: utf-8 -*-

"""
@Time    : 2025-10-21
@Author  : Rey
@Contact : reyxbo@163.com
@Explain : Dependency bind methods.
"""

from typing import overload, TYPE_CHECKING
from pydantic import EmailStr
from fastapi import FastAPI, Request, UploadFile
from fastapi.params import (
    Depends,
    Path,
    Query,
    Header,
    Cookie,
    Body,
    Form,
    File as Forms
)
from reydb.rconn import DatabaseConnectionAsync
from reydb.rorm import DatabaseORMSessionAsync
from reykit.rbase import StaticMeta, Singleton, throw

from .rbase import ServerBase, depend_pass

if TYPE_CHECKING:
    from .rauth import TokenData, User
    from .rserver import Server

__all__ = (
    'ServerBindInstanceDatabaseSuper',
    'ServerBindInstanceDatabaseConnection',
    'ServerBindInstanceDatabaseSession',
    'ServerBindInstance',
    'ServerBind',
    'Bind'
)

class ServerBindInstanceDatabaseSuper(ServerBase):
    """
    Server API bind parameter build database instance super type.
    """

    def __getattr__(self, name: str) -> Depends:
        """
        Create dependencie instance of asynchronous database.

        Parameters
        ----------
        name : Database engine name.
        mode : Mode.
            - `Literl['sess']`: Create ORM session instance.
            - `Literl['conn']`: Create connection instance.

        Returns
        -------
        Dependencie instance.
        """

        async def depend_func(server: 'Server' = Bind.server):
            """
            Dependencie function of asynchronous database.
            """

            # Check.
            if server.db is None:
                throw(TypeError, server.db)

            # Parameter.
            engine = server.db[name]

            # Context.
            match self:
                case ServerBindInstanceDatabaseConnection():
                    async with engine.connect() as conn:
                        yield conn
                case ServerBindInstanceDatabaseSession():
                    async with engine.orm.session() as sess:
                        yield sess

        # Create.
        depend = Depends(depend_func)

        return depend

    @overload
    def __getitem__(self, engine: str) -> DatabaseConnectionAsync: ...

    __getitem__ = __getattr__

class ServerBindInstanceDatabaseConnection(ServerBindInstanceDatabaseSuper, Singleton):
    """
    Server API bind parameter build database connection instance type, singleton mode.
    """

class ServerBindInstanceDatabaseSession(ServerBindInstanceDatabaseSuper, Singleton):
    """
    Server API bind parameter build database session instance type, singleton mode.
    """

class ServerBindInstance(ServerBase, Singleton):
    """
    Server API bind parameter build instance type.
    """

    @property
    def path(self) -> Path:
        """
        Path instance.
        """

        # Build.
        path = Path()

        return path

    @property
    def query(self) -> Query:
        """
        Query instance.
        """

        # Build.
        query = Query()

        return query

    @property
    def query_n(self) -> Query:
        """
        Query instance, default `None`.
        """

        # Build.
        query = Query(None)

        return query

    @property
    def header(self) -> Header:
        """
        Header instance.
        """

        # Build.
        header = Header()

        return header

    @property
    def header_n(self) -> Header:
        """
        Header instance, default `None`.
        """

        # Build.
        header = Header(None)

        return header

    @property
    def cookie(self) -> Cookie:
        """
        Cookie instance.
        """

        # Build.
        cookie = Cookie()

        return cookie

    @property
    def cookie_n(self) -> Cookie:
        """
        Cookie instance, default `None`.
        """

        # Build.
        cookie = Cookie(None)

        return cookie

    @property
    def body(self) -> Body:
        """
        Body instance.
        """

        # Build.
        body = Body()

        return body

    @property
    def body_n(self) -> Body:
        """
        Body instance, default `None`.
        """

        # Build.
        body = Body(None)

        return body

    @property
    def body_k(self) -> Body:
        """
        Body instance of parameter `embed` is `True`.
        """

        # Build.
        body = Body(embed=True)

        return body

    @property
    def body_kn(self) -> Body:
        """
        Body instance of parameter `embed` is `True`, default `None`.
        """

        # Build.
        body = Body(None, embed=True)

        return body

    @property
    def form(self) -> Form:
        """
        Form instance.
        """

        # Build.
        form = Form()

        return form

    @property
    def form_n(self) -> Form:
        """
        Form instance, default `None`.
        """

        # Build.
        form = Form(None)

        return form

    @property
    def forms(self) -> Forms:
        """
        Forms instance.
        """

        # Build.
        forms = Forms()

        return forms

    @property
    def forms_n(self) -> Forms:
        """
        Forms instance, default `None`.
        """

        # Build.
        forms = Forms(None)

        return forms

async def depend_server(request: Request) -> 'Server':
    """
    Dependencie function of now Server instance.

    Parameters
    ----------
    request : Request.

    Returns
    -------
    Server.
    """

    # Get.
    app: FastAPI = request.app
    server: Server = app.extra['server']

    return server

class ServerBind(ServerBase, metaclass=StaticMeta):
    """
    Server API bind parameter type.
    """

    Request = Request
    'Reqeust instance dependency type.'
    Path = Path
    'URL source path dependency type.'
    Query = Query
    'URL query parameter dependency type.'
    Header = Header
    'Request header parameter dependency type.'
    Cookie = Cookie
    'Request header cookie parameter dependency type.'
    Body = Body
    'Request body JSON parameter dependency type.'
    Form = Form
    'Request body form parameter dependency type.'
    Forms = Forms
    'Request body multiple forms parameter dependency type.'
    File = UploadFile
    'Type hints file type.'
    Depend = Depends
    'Dependency type.'
    Email= EmailStr
    Conn = DatabaseConnectionAsync
    Sess = DatabaseORMSessionAsync
    server: Depend = Depend(depend_server)
    'Server instance dependency type.'
    i = ServerBindInstance()
    'Server API bind parameter build instance.'
    conn = ServerBindInstanceDatabaseConnection()
    'Server API bind parameter asynchronous database connection.'
    sess = ServerBindInstanceDatabaseSession()
    'Server API bind parameter asynchronous database session.'
    token: Depend = depend_pass
    'Server authentication token dependency type.'
    user: Depend = depend_pass
    'Current session user data dependency type.'
    if TYPE_CHECKING:
        Server = Server
        TokenData = TokenData
        User = User
    else:
        Server = TokenData = User = None

Bind = ServerBind
