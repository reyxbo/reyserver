# !/usr/bin/env python
# -*- coding: utf-8 -*-

"""
@Time    : 2025-10-21
@Author  : Rey
@Contact : reyxbo@163.com
@Explain : Dependency bind methods.
"""

from typing import TypedDict, NotRequired, Literal, overload, TYPE_CHECKING
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
from fastapi.security import OAuth2PasswordBearer
from reydb.rconn import DatabaseConnectionAsync
from reydb.rorm import DatabaseORMSessionAsync
from reykit.rbase import StaticMeta, Singleton, throw
from reykit.rdata import decode_jwt
from reykit.ros import get_md5
from reykit.rre import search_batch

from .rbase import ServerBase, exit_api, depend_pass

if TYPE_CHECKING:
    from .rauth import Token, TokenStr
    from .rfile import DatabaseORMTableInfo, DatabaseORMTableData
    from .rserver import Server
    type FileModels = tuple[DatabaseORMTableInfo, DatabaseORMTableData]

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

        async def depend_func(request: Request):
            """
            Dependencie function of asynchronous database.
            """

            # Parameter.
            app: FastAPI = request.app
            server: Server = app.extra['server']

            ## Check.
            if server.db is None:
                throw(TypeError, server.db)

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

bearer = OAuth2PasswordBearer(
    tokenUrl='/api/auth/token',
    scheme_name='OAuth2Password',
    description='Authentication of OAuth2 password model.',
    auto_error=False
)

async def depend_token(
    request: Request,
    server: 'Server' = Depends(depend_server),
    token_str: 'TokenStr | None' = Depends(bearer)
) -> 'Token':
    """
    Dependencie function of authentication token.
    If the verification fails, then response status code is 401 or 403.

    Parameters
    ----------
    request : Request.
    server : Server.
    token_str : Authentication token string.

    Returns
    -------
    Token data dictionary.
    """

    # Check.
    if not server.is_started_auth:
        return

    # Parameter.
    key = server.api_auth_key
    api_path = f'{request.method} {request.url.path}'

    # Cache.
    token: Token | None = getattr(request.state, 'token', None)

    # Decode.
    if token is None:
        token: Token | None = decode_jwt(token_str, key)
        if token is None:
            exit_api(401)
        request.state.token = token

    # Authentication.
    perm_apis = [
        f'^{pattern}'
        for pattern in token['perm_apis']
    ]
    result = search_batch(api_path, *perm_apis)
    if result is None:
        exit_api(403)

    return token

class User(ServerBase):
    """
    User data type.
    """

    def __init__(self, token: 'Token') -> None:
        """
        Build instance attributes.

        Parameters
        ----------
        token : Token data.
        """

        # Build.
        self.user_id = token['user_id']

async def depend_user(token: 'Token' = Depends(depend_token)) -> User:
    """
    Dependencie function of user data.

    Parameters
    ----------
    token : token data.

    Returns
    -------
    User data.
    """

    # Instance.
    user = User(token)

    return user

async def depend_file(
    file: UploadFile = Forms(),
    name: str | None = Forms(None),
    note: str | None = Forms(None),
    sess: DatabaseORMSessionAsync = ServerBindInstanceDatabaseSession().file,
    server: 'Server' = Depends(depend_server)
) -> 'FileModels':
    """
    Upload file data.

    Parameters
    ----------
    file : File instance.
    name : File name.
        - `None`: Use `file.filename`.
    note : File note.

    Returns
    -------
    File information and data.
    """

    from .rfile import DatabaseORMTableInfo, DatabaseORMTableData

    # Parameter.
    file_store = server.api_file_store
    file_bytes = await file.read()
    file_md5 = get_md5(file_bytes)
    file_size = len(file_bytes)
    if name is None:
        name = file.filename

    # Upload.
    file_path = file_store.index(file_md5)

    ## Data.
    if file_path is None:
        file_path = file_store.store(file_bytes)
        file_relpath = file_store.get_relpath(file_path)
        model_data = DatabaseORMTableData(
            md5=file_md5,
            size=file_size,
            path=file_relpath
        )
        await sess.add(model_data)

    ## Information.
    model_info = DatabaseORMTableInfo(
        md5=file_md5,
        name=name,
        note=note
    )
    await sess.add(model_info)

    # Get ID.
    await sess.flush()

    return model_info, model_data

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
    UploadFile = UploadFile
    'Type hints upload file type.'
    Depend = Depends
    'Dependency type.'
    Email= EmailStr
    Conn = DatabaseConnectionAsync
    Sess = DatabaseORMSessionAsync
    i = ServerBindInstance()
    'Server API bind parameter build instance.'
    conn = ServerBindInstanceDatabaseConnection()
    'Server API bind parameter asynchronous database connection.'
    sess = ServerBindInstanceDatabaseSession()
    'Server API bind parameter asynchronous database session.'
    server = Depend(depend_server)
    'Server global instance dependency type.'
    token = Depend(depend_token)
    'Server authentication token dependency type.'
    user = Depend(depend_user)
    'Current session user data dependency type.'
    file = Depend(depend_file)
    'Upload file data dependency type.'
    User = User
    if TYPE_CHECKING:
        Server = Server
        Token = Token
        FileModelInfo = DatabaseORMTableInfo
        FileModelData = DatabaseORMTableData
        FileModels = FileModels
    else:
        Server = Token = FileModelInfo = FileModelData = FileModels = None

Bind = ServerBind
