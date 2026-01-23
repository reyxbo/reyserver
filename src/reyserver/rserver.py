# !/usr/bin/env python
# -*- coding: utf-8 -*-

"""
@Time    : 2025-10-05
@Author  : Rey
@Contact : reyxbo@163.com
@Explain : Server methods.
"""


from typing import Literal
from collections.abc import Sequence, Callable, Coroutine
from inspect import iscoroutinefunction
from contextlib import asynccontextmanager, _AsyncGeneratorContextManager
from uvicorn import run as uvicorn_run
from starlette.middleware.base import _StreamingResponse
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi_cache import FastAPICache
from redis.asyncio import Redis
from reydb import DatabaseAsync
from reykit.rbase import CoroutineFunctionSimple, Singleton, throw
from reykit.ros import FileStore
from reykit.rrand import randchar

from .rbase import ServerBase
from .rbind import Bind
from .rcache import init_cache


__all__ = (
    'Server',
)


class Server(ServerBase, Singleton):
    """
    Server type, singleton mode.
    Based on `fastapi` and `uvicorn` package.
    Can view document api '/docs', '/redoc', '/openapi.json'.
    """

    is_started_auth: bool = False
    'Whether start authentication.'
    api_public_dir: str
    'Public directory.'
    api_redirect_server_url: str
    'Target server URL of redirect all requests.'
    api_auth_key: str
    'Authentication API JWT encryption key.'
    api_auth_sess_seconds: int
    'Authentication API session valid seconds.'
    api_file_store: FileStore
    'File API store instance.'


    def __init__(
        self,
        db: DatabaseAsync | None = None,
        db_warm: bool = False,
        redis: Redis | None = None,
        redis_expire: int | None = None,
        depend: CoroutineFunctionSimple | Sequence[CoroutineFunctionSimple] | None = None,
        before: CoroutineFunctionSimple | Sequence[CoroutineFunctionSimple] | None = None,
        after: CoroutineFunctionSimple | Sequence[CoroutineFunctionSimple] | None = None,
        debug: bool = False
    ) -> None:
        """
        Build instance attributes.

        Parameters
        ----------
        db : Asynchronous database, include database engines required for APIs.
        db_warm : Whether database pre create connection to warm all pool.
        redis : Asynchronous Redis, activate cache function.
        redis_expire : Redis cache expire seconds.
        depend : Global api dependencies.
        before : Execute before server start.
        after : Execute after server end.
        debug : Whether use development mode debug server.
        """

        # Parameter.
        if depend is None:
            depend = ()
        elif iscoroutinefunction(depend):
            depend = (depend,)
        depend = [
            Bind.Depend(task)
            for task in depend
        ]
        lifespan = self.__create_lifespan(
            before,
            after,
            db_warm,
            redis_expire
        )

        # Build.
        self.db = db
        self.redis = redis
        self.app = FastAPI(
            dependencies=depend,
            lifespan=lifespan,
            debug=debug,
            server=self
        )

        # Middleware
        self.wrap_middleware = self.app.middleware('http')
        'Decorator, add middleware to APP.'
        self.app.add_middleware(GZipMiddleware)
        self.app.add_middleware(TrustedHostMiddleware)
        self.__add_base_middleware()


    def __create_lifespan(
        self,
        before: CoroutineFunctionSimple | Sequence[CoroutineFunctionSimple] | None,
        after: CoroutineFunctionSimple | Sequence[CoroutineFunctionSimple] | None,
        db_warm: bool,
        redis_expire: int | None
    ) -> _AsyncGeneratorContextManager[None, None]:
        """
        Create asynchronous function of lifespan manager.

        Parameters
        ----------
        before : Execute before server start.
        after : Execute after server end.
        db_warm : Whether database pre create connection to warm all pool.
        redis_expire : Redis cache expire seconds.

        Returns
        -------
        Asynchronous function.
        """

        # Parameter.
        if before is None:
            before = ()
        elif iscoroutinefunction(before):
            before = (before,)
        if after is None:
            after = ()
        elif iscoroutinefunction(after):
            after = (after,)


        @asynccontextmanager
        async def lifespan(app: FastAPI):
            """
            Server lifespan manager.

            Parameters
            ----------
            app : Server APP.
            """

            # Before.
            for task in before:
                await task()

            ## Databse.
            if db_warm:
                await self.db.warm_all()

            ## Redis.
            if self.redis is not None:
                init_cache(self.redis, redis_expire)
            else:
                FastAPICache._enable = False

            # Runing.
            yield

            # After.
            for task in after:
                await after()

            ## Database.
            if self.db is not None:
                await self.db.dispose_all()


        return lifespan


    def __add_base_middleware(self) -> None:
        """
        Add base middleware.
        """

        # Add.
        @self.wrap_middleware
        async def base_middleware(
            request: Request,
            call_next: Callable[[Request], Coroutine[None, None, _StreamingResponse]]
        ) -> _StreamingResponse:
            """
            Base middleware.

            Parameters
            ----------
            Reqeust : Request instance.
            call_next : Next middleware.
            """

            # Before.
            ...

            # Next.
            response = await call_next(request)

            # After.
            if (
                response.status_code == 200
                and request.method == 'POST'
            ):
                response.status_code = 201
            elif response.status_code == 401:
                response.headers.setdefault('WWW-Authenticate', 'Bearer')

            return response


    def run(
        self,
        app: str | None = None,
        host: str = '127.0.0.1',
        port: int = 8000,
        workers: int = 1,
        ssl_cert: str | None = None,
        ssl_key: str | None = None
    ) -> None:
        """
        Run server.

        Parameters
        ----------
        app : Application or function path.
            - `None`: Cannot use parameter `workers`.
            - `Application`: format is `module[.sub....]:var[.attr....]` (e.g. `module.sub:server.app`).
            - `Function`: format is `module[.sub....]:func` (e.g. `module.sub:main`).
        host : Server host.
        port: Server port.
        workers: Number of server work processes.
        ssl_cert : SSL certificate file path.
        ssl_key : SSL key file path.

        Examples
        --------
        Single work process.
        >>> server = Server(db)
        >>> server.run()

        Multiple work processes.
        >>> server = Server(db)
        >>> if __name__ == '__main__':
        >>>     server.run('module.sub:server.app', workers=2)
        """

        # Parameter.
        if type(ssl_cert) != type(ssl_key):
            throw(AssertionError, ssl_cert, ssl_key)
        if app is None:
            app = self.app
        if workers == 1:
            workers = None

        # Run.
        uvicorn_run(
            app,
            host=host,
            port=port,
            workers=workers,
            ssl_certfile=ssl_cert,
            ssl_keyfile=ssl_key
        )


    __call__ = run


    def set_doc(
        self,
        version: str | None = None,
        title: str | None = None,
        summary: str | None = None,
        desc: str | None = None,
        contact: dict[Literal['name', 'email', 'url'], str] | None = None
    ) -> None:
        """
        Set server document.

        Parameters
        ----------
        version : Server version.
        title : Server title.
        summary : Server summary.
        desc : Server description.
        contact : Server contact information.
        """

        # Parameter.
        set_dict = {
            'version': version,
            'title': title,
            'summary': summary,
            'description': desc,
            'contact': contact
        }

        # Set.
        for key, value in set_dict.items():
            if value is not None:
                setattr(self.app, key, value)


    def set_cors(
            self,
            origin: str | Sequence[str],
            method: str | Sequence[str] = "GET"
        ) -> None:
        """
        Set CORS policy.

        Parameters
        ----------
        origin : Allow origin host. Wildcard is `*`.
        method : Allow request method. Wildcard is `*`.
        """

        # Parameter.
        if type(origin) == str:
            origin = (origin,)
        if type(method) == str:
            method = (method,)

        # Set.
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=origin,
            allow_methods=method
        )


    def add_api_test(self) -> None:
        """
        Add test API.
        """

        from .rtest import router_test

        # Add.
        self.app.include_router(router_test, tags=['test'])


    def add_api_public(self, public_dir: str) -> None:
        """
        Add public API,
        mapping `{public_dir}/index.html` to `GET /`,
        mapping `{public_dir}/{path}` to `GET `/public/{path:path}`.

        Parameters
        ----------
        public_dir : Public directory.
        """

        from .rpublic import router_public

        # Add.
        self.api_public_dir = public_dir
        subapp = StaticFiles(directory=public_dir)
        self.app.mount('/public', subapp)
        self.app.include_router(router_public, tags=['public'])


    def add_api_redirect_all(self, server_url: str) -> None:
        """
        Add redirect all API.
        Redirect all requests to the target server.

        Parameters
        ----------
        server_url : Target server URL.
        """

        from .rredirect import router_redirect

        # Add.
        self.api_redirect_server_url = server_url
        self.app.include_router(router_redirect, tags=['redirect'])


    def add_api_auth(self, key: str | None = None, sess_seconds: int = 28800) -> None:
        """
        Add authentication API.
        Note: must include database engine of `auth` name.

        Parameters
        ----------
        key : JWT encryption key.
            - `None`: Random 32 length string.
        sess_seconds : Session valid seconds.
        """

        from .rauth import build_db_auth, router_auth

        # Parameter.
        if key is None:
            key = randchar(32)

        # Database.
        if (
            self.db is None
            or 'auth' not in self.db
        ):
            throw(TypeError, self.db)
        engine = self.db.auth
        build_db_auth(engine)

        # Add.
        self.api_auth_key = key
        self.api_auth_sess_seconds = sess_seconds
        self.app.include_router(router_auth, tags=['auth'])
        self.is_started_auth = True


    def add_api_file(self, file_dir: str = 'file') -> None:
        """
        Add file API.
        Note: must include database engine of `file` name.

        Parameters
        ----------
        file_dir : File API store directory path.
        """

        from .rfile import build_db_file, router_file

        # Database.
        if (
            self.db is None
            or 'file' not in self.db
        ):
            throw(TypeError, self.db)
        engine = self.db.file
        build_db_file(engine)

        # Add.
        self.api_file_store = FileStore(file_dir)
        self.app.include_router(router_file, tags=['file'], dependencies=(Bind.token,))


Bind.Server = Server
