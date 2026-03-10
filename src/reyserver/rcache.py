# !/usr/bin/env python
# -*- coding: utf-8 -*-

"""
@Time    : 2025-10-25
@Author  : Rey
@Contact : reyxbo@163.com
@Explain : Cache methods.
"""

from typing import Any
from collections.abc import Callable
from inspect import  iscoroutinefunction
from fastapi import Request, Response
from fastapi_cache import FastAPICache
from fastapi_cache.coder import PickleCoder
from fastapi_cache.backends.redis import RedisBackend
from fastapi_cache.decorator import cache as fastapi_cache_cache
from redis.asyncio import Redis
from reykit.rbase import CallableT
from reykit.ros import get_md5
from reykit.rre import sub

__all__ = (
    'init_cache',
    'wrap_cache'
)

def init_cache(redis: Redis, redis_expire: int | None = None) -> None:
    """
    Initialize cache based on Redis.

    Parameters
    ----------
    redis : Asynchronous Redis
    redis_expire : Redis cache expire seconds.
    """

    def key_builder(
        func: Callable,
        namespace: str,
        request: Request | None,
        response: Response | None,
        args: tuple,
        kwargs: dict[str, Any],
    ) -> str:
        """
        Cache key builder.

        Parameters
        ----------
        func : Decorated function.
        namespace : Cache key prefix.
        request : API Request.
        response : API response.
        args : Position arguments of decorated function.
        kwargs : Keyword arguments of decorated function.
        """

        # Parameter.
        data = f'{func.__module__}:{func.__name__}:{args}:{kwargs}'
        pattern = r' object at 0x[0-9a-fA-F]+>'
        data = sub(pattern, data, '>')

        # Build.
        key = get_md5(data)

        return key

    # Initialize.
    backend = RedisBackend(redis)
    FastAPICache.init(
        backend,
        expire=redis_expire,
        coder=PickleCoder,
        key_builder=key_builder
    )

def wrap_cache(func_or_expire: CallableT | int | None = None) -> CallableT | Callable[[CallableT], CallableT]:
    """
    Decorator, use Redis cache.
    When Redis is not set, then skip.

    Parameters
    ----------
    func_or_expire : Decorated function or Redis cache expire seconds.

    Returns
    -------
    Decorated function or decorator.

    Examples
    --------
    No parameter.
    >>> @wrap_cache
    >>> def foo(): ...

    Set parameter.
    >>> @wrap_cache(60)
    >>> def foo(): ...
    """

    # Decorate.

    ## No parameter.
    if callable(func_or_expire):
        decorator_cache = fastapi_cache_cache()
        wrapped_func = decorator_cache(func_or_expire)
        wrapped_func.__wrapped__ = func_or_expire
        if 'return' in func_or_expire.__annotations__:
            wrapped_func.__annotations__['return'] = func_or_expire.__annotations__['return']
        return wrapped_func

    ## With parameter.
    else:
        def wrap(func):
            decorator_cache = fastapi_cache_cache(func_or_expire)
            wrapped_func = decorator_cache(func)
            wrapped_func.__wrapped__ = func
            if 'return' in func.__annotations__:
                wrapped_func.__annotations__['return'] = func.__annotations__['return']
            return wrapped_func
        return wrap
