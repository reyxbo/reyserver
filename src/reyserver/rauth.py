# !/usr/bin/env python
# -*- coding: utf-8 -*-

"""
@Time    : 2025-10-10
@Author  : Rey
@Contact : reyxbo@163.com
@Explain : Authentication methods.
"""

from typing import Any, TypedDict, NotRequired, Literal
from datetime import datetime as Datetime
from fastapi import APIRouter, Request
from fastapi.security import OAuth2PasswordBearer
from reydb import rorm, DatabaseEngine, DatabaseEngineAsync
from reykit.rbase import throw
from reykit.rdata import encode_jwt, decode_jwt, hash_bcrypt, is_hash_bcrypt
from reykit.rre import PATTERN_PHONE, search, search_batch
from reykit.rtime import now

from .rbase import ServerBase, exit_api
from .rbind import Bind

__all__ = (
    'DatabaseORMTableUser',
    'DatabaseORMTableRole',
    'DatabaseORMTablePerm',
    'DatabaseORMTableUserRole',
    'DatabaseORMTableRolePerm',
    'build_db_auth',
    'router_auth'
)

User = TypedDict(
    'UserData',
    {
        'create_time': float,
        'update_time': float,
        'user_id': int,
        'user_name': str,
        'role_names': list[str],
        'perm_names': list[str],
        'perm_apis': list[str],
        'email': str | None,
        'phone': str | None,
        'avatar': int | None,
        'password': NotRequired[str]
    }
)
TokenData = TypedDict(
    'TokenData',
    {
        'sub': str,
        'iat': int,
        'nbf': int,
        'exp': int,
        'user_id': int,
        'perm_apis': list[str]
    }
)
Token = str
JSONToken = TypedDict(
    'JSONToken',
    {
        'access_token': Token,
        'token_type': Literal['Bearer']
    }
)
UserExists = TypedDict('UserExists', {'is_exists': bool})

STANDARD_USER_ROLE_ID = 2

class DatabaseORMTableUser(rorm.Table):
    """
    Database "user" table ORM model.
    """

    __name__ = 'user'
    __comment__ = 'User information table.'
    create_time: rorm.Datetime = rorm.Field(field_default=':time', not_null=True, index_n=True, comment='Record create time.')
    update_time: rorm.Datetime = rorm.Field(field_default=':time', not_null=True, index_n=True, comment='Record update time.')
    user_id: int = rorm.Field(key_auto=True, comment='User ID.')
    name: str = rorm.Field(rorm.types.VARCHAR(50), not_null=True, index_u=True, comment=f'User name.', len_min=3)
    password: str = rorm.Field(rorm.types.CHAR(60), not_null=True, comment='User password, encrypted with "bcrypt".', len_min=6)
    email: rorm.Email = rorm.Field(rorm.types.VARCHAR(255), index_u=True, comment='User email.')
    phone: str = rorm.Field(rorm.types.CHAR(11), index_u=True, comment=f'User phone.', re=PATTERN_PHONE)
    avatar: int = rorm.Field(comment='User avatar file ID.')
    is_valid: bool = rorm.Field(field_default='TRUE', not_null=True, comment='Is the valid.')

    @rorm.wrap_validate_filed('name')
    @classmethod
    def check_name(cls, name: str):
        if search('^[0-9a-z-_]+$', name) is None:
            throw(ValueError, text='containing characters not allowed')
        if search('[a-z]', name) is None:
            throw(ValueError, text='must contain lowercase letters')
        if search('^[-_]|[-_]$', name) is not None:
            throw(ValueError, text='the start and end cannot be the character "-_"')
        if search('[-_]{2}', name) is not None:
            throw(ValueError, text='must not be contain consecutive characters "-_"')

class DatabaseORMTableRole(rorm.Table):
    """
    Database "role" table ORM model.
    """

    __name__ = 'role'
    __comment__ = 'Role information table.'
    create_time: rorm.Datetime = rorm.Field(field_default=':time', not_null=True, index_n=True, comment='Record create time.')
    update_time: rorm.Datetime = rorm.Field(field_default=':time', arg_default=now, not_null=True, index_n=True, comment='Record update time.')
    role_id: int = rorm.Field(rorm.types.SMALLINT, key_auto=True, comment='Role ID.')
    name: str = rorm.Field(rorm.types.VARCHAR(50), not_null=True, index_u=True, comment='Role name.')
    desc: str = rorm.Field(rorm.types.VARCHAR(500), comment='Role description.')
    is_valid: bool = rorm.Field(field_default='TRUE', not_null=True, comment='Is the valid.')

class DatabaseORMTablePerm(rorm.Table):
    """
    Database "perm" table ORM model.
    """

    __name__ = 'perm'
    __comment__ = 'API permission information table.'
    create_time: rorm.Datetime = rorm.Field(field_default=':time', not_null=True, index_n=True, comment='Record create time.')
    update_time: rorm.Datetime = rorm.Field(field_default=':time', arg_default=now, not_null=True, index_n=True, comment='Record update time.')
    perm_id: int = rorm.Field(rorm.types.SMALLINT, key_auto=True, comment='Permission ID.')
    name: str = rorm.Field(rorm.types.VARCHAR(50), not_null=True, index_u=True, comment='Permission name.')
    desc: str = rorm.Field(rorm.types.VARCHAR(500), comment='Permission description.')
    api: str = rorm.Field(
        rorm.types.VARCHAR(1000),
        comment=r'API method and resource path regular expression "match" pattern, case insensitive, format is "{method} {path}" (e.g. "GET /users").'
    )
    is_valid: bool = rorm.Field(field_default='TRUE', not_null=True, comment='Is the valid.')

class DatabaseORMTableUserRole(rorm.Table):
    """
    Database "user_role" table ORM model.
    """

    __name__ = 'user_role'
    __comment__ = 'User and role association table.'
    create_time: rorm.Datetime = rorm.Field(field_default=':time', not_null=True, index_n=True, comment='Record create time.')
    update_time: rorm.Datetime = rorm.Field(field_default=':time', arg_default=now, not_null=True, index_n=True, comment='Record update time.')
    user_id: int = rorm.Field(key=True, comment='User ID.')
    role_id: int = rorm.Field(rorm.types.SMALLINT, key=True, comment='Role ID.')

class DatabaseORMTableRolePerm(rorm.Table):
    """
    Database "role_perm" table ORM model.
    """

    __name__ = 'role_perm'
    __comment__ = 'role and permission association table.'
    create_time: rorm.Datetime = rorm.Field(field_default=':time', not_null=True, index_n=True, comment='Record create time.')
    update_time: rorm.Datetime = rorm.Field(field_default=':time', arg_default=now, not_null=True, index_n=True, comment='Record update time.')
    role_id: int = rorm.Field(rorm.types.SMALLINT, key=True, comment='Role ID.')
    perm_id: int = rorm.Field(rorm.types.SMALLINT, key=True, comment='Permission ID.')

class DatabaseORMModelUserOut(rorm.Model):
    """
    Database user out ORM model.
    """

    create_time: rorm.Datetime = rorm.Field(field_default=':time', not_null=True, index_n=True, comment='Record create time.')
    update_time: rorm.Datetime = rorm.Field(field_default=':time', not_null=True, index_n=True, comment='Record update time.')
    user_id: int = rorm.Field(key_auto=True, comment='User ID.')
    name: str = rorm.Field(rorm.types.VARCHAR(50), not_null=True, index_u=True, comment=f'User name.', len_min=3)
    email: rorm.Email = rorm.Field(rorm.types.VARCHAR(255), index_u=True, comment='User email.')
    phone: str = rorm.Field(rorm.types.CHAR(11), index_u=True, comment=f'User phone.', re=PATTERN_PHONE)
    avatar: int = rorm.Field(comment='User avatar file ID.')

def build_db_auth(engine: DatabaseEngine | DatabaseEngineAsync) -> None:
    """
    Check and build "auth" database tables.

    Parameters
    ----------
    db : Database engine instance.
    """

    # Set parameter.

    ## Table.
    tables = [
        DatabaseORMTableUser,
        DatabaseORMTableRole,
        DatabaseORMTablePerm,
        DatabaseORMTableUserRole,
        DatabaseORMTableRolePerm
    ]

    ## View stats.
    views_stats = [
        {
            'table': 'stats',
            'items': [
                {
                    'name': 'user_count',
                    'select': (
                        'SELECT COUNT(1)\n'
                        'FROM "user"'
                    ),
                    'comment': 'User information count.'
                },
                {
                    'name': 'role_count',
                    'select': (
                        'SELECT COUNT(1)\n'
                        'FROM "role"'
                    ),
                    'comment': 'Role information count.'
                },
                {
                    'name': 'perm_count',
                    'select': (
                        'SELECT COUNT(1)\n'
                        'FROM "perm"'
                    ),
                    'comment': 'Permission information count.'
                },
                {
                    'name': 'user_day_count',
                    'select': (
                        'SELECT COUNT(1)\n'
                        'FROM "user"\n'
                        'WHERE DATE_PART(\'day\', NOW() - "create_time") = 0'
                    ),
                    'comment': 'User information count in the past day.'
                },
                {
                    'name': 'user_week_count',
                    'select': (
                        'SELECT COUNT(1)\n'
                        'FROM "user"\n'
                        'WHERE DATE_PART(\'day\', NOW() - "create_time") <= 6'
                    ),
                    'comment': 'User information count in the past week.'
                },
                {
                    'name': 'user_month_count',
                    'select': (
                        'SELECT COUNT(1)\n'
                        'FROM "user"\n'
                        'WHERE DATE_PART(\'day\', NOW() - "create_time") <= 29'
                    ),
                    'comment': 'User information count in the past month.'
                },
                {
                    'name': 'user_last_time',
                    'select': (
                        'SELECT MAX("create_time")\n'
                        'FROM "user"'
                    ),
                    'comment': 'User last record create time.'
                }
            ]
        }
    ]

    # Build.
    engine.sync_engine.build.build(tables=tables, views_stats=views_stats, skip=True)

bearer = OAuth2PasswordBearer(
    tokenUrl='/auth/token',
    scheme_name='OAuth2Password',
    description='Authentication of OAuth2 password model.',
    auto_error=False
)

async def depend_token(
    request: Request,
    server: Bind.Server = Bind.server,
    token: Token | None = Bind.Depend(bearer)
) -> TokenData:
    """
    Dependencie function of authentication token.
    If the verification fails, then response status code is 401 or 403.

    Parameters
    ----------
    request : Request.
    server : Server.
    token : Authentication token.

    Returns
    -------
    Token data.
    """

    # Check.
    if not server.is_started_auth:
        return

    # Parameter.
    key = server.api_auth_key
    api_path = f'{request.method} {request.url.path}'

    # Cache.
    token_data: TokenData | None = getattr(request.state, 'token_data', None)

    # Decode.
    if token_data is None:
        token_data: TokenData | None = decode_jwt(token, key)
        if token_data is None:
            exit_api(401)
        request.state.token_data = token_data

    # Authentication.
    perm_apis = [
        f'^{pattern}'
        for pattern in token_data['perm_apis']
    ]
    result = search_batch(api_path, *perm_apis)
    if result is None:
        exit_api(403)

    return token_data

class User(ServerBase):
    """
    User data.
    """

    def __init__(self, token: TokenData) -> None:
        """
        Build instance attributes.

        Parameters
        ----------
        token : Token data.
        """

        # Build.
        self.user_id = token['user_id']

async def depend_user(token: TokenData = Bind.Depend(depend_token)) -> User:
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

Bind.TokenData = TokenData
Bind.token = Bind.Depend(depend_token)
Bind.User = User
Bind.user = Bind.Depend(depend_user)

router_auth = APIRouter()

async def get_user_data(
    conn: Bind.Conn,
    index: str | int,
    index_type: Literal['user_id', 'name', 'email', 'phone', 'account'],
    filter_invalid: bool = True
) -> User | None:
    """
    Get user data.

    Parameters
    ----------
    conn: Asyncronous database connection.
    index : User index.
    index_type : User index type.
        - "Literal['user_id']: User ID.
        - "Literal['name']": User name.
        - "Literal['email']": User email.
        - "Literal['phone']": User phone mumber.
        - "Literal['account']": User name or email or phone number.
    filter_invalid : Whether filter invalid user.

    Returns
    -------
    User data or null.
    """

    # Parameter.
    if filter_invalid:
        if index_type == 'account':
            sql_where_user = (
                '    WHERE (\n'
                '        (\n'
                '            "name" = :index\n'
                '            or "email" = :index\n'
                '            or "phone" = :index\n'
                '        )\n'
                '        AND "is_valid" = TRUE\n'
                '    )\n'
            )
        else:
            sql_where_user = (
                '    WHERE (\n'
                f'        "{index_type}" = :index\n'
                '        AND "is_valid" = TRUE\n'
                '    )\n'
            )
        sql_where_role = sql_where_perm = '    WHERE "is_valid" = TRUE\n'
    else:
        if index_type == 'account':
            sql_where_user = (
                '    WHERE (\n'
                '        "name" = :index\n'
                '        or "email" = :index\n'
                '        or "phone" = :index\n'
                '    )\n'
            )
        else:
            sql_where_user = f'    WHERE "{index_type}" = :index\n'
        sql_where_role = sql_where_perm = ''

    # Get.
    sql = (
        'SELECT ANY_VALUE("create_time") AS "create_time",\n'
        '    ANY_VALUE("phone") AS "phone",\n'
        '    ANY_VALUE("update_time") AS "update_time",\n'
        '    ANY_VALUE("user"."user_id") AS "user_id",\n'
        '    ANY_VALUE("user"."name") AS "user_name",\n'
        '    ANY_VALUE("password") AS "password",\n'
        '    ANY_VALUE("email") AS "email",\n'
        '    ANY_VALUE("avatar") AS "avatar",\n'
        '    STRING_AGG(DISTINCT "role"."name", \';\') AS "role_names",\n'
        '    STRING_AGG(DISTINCT "perm"."name", \';\') AS "perm_names",\n'
        '    STRING_AGG(DISTINCT "perm"."api", \';\') AS "perm_apis"\n'
        'FROM (\n'
        '    SELECT "create_time", "update_time", "user_id", "password", "name", "email", "phone", "avatar"\n'
        '    FROM "user"\n'
        f'{sql_where_user}'
        '    LIMIT 1\n'
        ') as "user"\n'
        'LEFT JOIN (\n'
        '    SELECT "user_id", "role_id"\n'
        '    FROM "user_role"\n'
        ') as "user_role"\n'
        'ON "user_role"."user_id" = "user"."user_id"\n'
        'LEFT JOIN (\n'
        '    SELECT "role_id", "name"\n'
        '    FROM "role"\n'
        f'{sql_where_role}'
        ') AS "role"\n'
        'ON "user_role"."role_id" = "role"."role_id"\n'
        'LEFT JOIN (\n'
        '    SELECT "role_id", "perm_id"\n'
        '    FROM "role_perm"\n'
        ') as "role_perm"\n'
        'ON "role_perm"."role_id" = "role"."role_id"\n'
        'LEFT JOIN (\n'
        '    SELECT "perm_id", "name", "api"\n'
        '    FROM "perm"\n'
        f'{sql_where_perm}'
        ') AS "perm"\n'
        'ON "role_perm"."perm_id" = "perm"."perm_id"\n'
        'GROUP BY "user"."user_id"'
    )
    result = await conn.execute(
        sql,
        index=index
    )

    # Extract.
    if result.empty:
        info = None
    else:
        row: dict[str, Datetime | Any] = result.to_row()
        if row['role_names'] is None:
            row['role_names'] = ''
        if row['perm_names'] is None:
            row['perm_names'] = ''
        if row['perm_apis'] is None:
            row['perm_apis'] = ''
        info: User = {
            'create_time': row['create_time'].timestamp(),
            'update_time': row['update_time'].timestamp(),
            'user_id': row['user_id'],
            'user_name': row['user_name'],
            'role_names': row['role_names'].split(';'),
            'perm_names': row['perm_names'].split(';'),
            'perm_apis': row['perm_apis'].split(';'),
            'email': row['email'],
            'phone': row['phone'],
            'avatar': row['avatar'],
            'password': row['password']
        }

    return info

def encode_token(
    data: User,
    key: str,
    seconds: int
) -> Token:
    """
    Encode data to token string.

    Parameters
    ----------
    data : User data.
    key : Authentication API JWT encryption key.
    seconds: Authentication API session valid seconds.

    Returns
    -------
    Token.
    """

    # Create.
    now_timestamp_s = now('timestamp_s')
    json: TokenData = {
        'sub': str(data['user_id']),
        'iat': now_timestamp_s,
        'nbf': now_timestamp_s,
        'exp': now_timestamp_s + seconds,
        'user_id': data['user_id'],
        'perm_apis': data['perm_apis']
    }
    token = encode_jwt(json, key)

    return token

@router_auth.post('/token')
async def get_token(
    account: str = Bind.i.form,
    password: str = Bind.i.form,
    conn: Bind.Conn = Bind.conn.auth,
    server: Bind.Server = Bind.server
) -> JSONToken:
    """
    Get token.

    Parameters
    ----------
    account : User account. User name or email or phone number.
    password : User password.

    Returns
    -------
    JSON with "token".
    """

    # Check.
    user_data = await get_user_data(conn, account, 'account')
    if user_data is None:
        exit_api(401)
    if not is_hash_bcrypt(password, user_data['password']):
        exit_api(401)

    # Token.
    token = encode_token(
        user_data,
        server.api_auth_key,
        server.api_auth_sess_seconds
    )

    # Response.
    response = {
        'access_token': token,
        'token_type': 'Bearer'
    }

    return response

@router_auth.post('/users')
async def create_user(
    model_user: DatabaseORMTableUser,
    conn: Bind.Conn = Bind.conn.auth,
    sess: Bind.Sess = Bind.sess.auth,
    server: Bind.Server = Bind.server
) -> JSONToken:
    """
    Create user.

    Parameters
    ----------
    model_user : User data model.

    Returns
    -------
    JSON with "token".
    """

    # Signup.
    model_user.password = hash_bcrypt(model_user.password).decode()
    await sess.add(model_user)
    await sess.flush()
    user_role = DatabaseORMTableUserRole(
        user_id=model_user.user_id,
        role_id=STANDARD_USER_ROLE_ID
    )
    await sess.add(user_role)
    user_id = model_user.user_id
    await sess.commit()

    # Token.
    user_data: User = await get_user_data(conn, user_id, 'user_id')
    token = encode_token(
        user_data,
        server.api_auth_key,
        server.api_auth_sess_seconds
    )

    # Response.
    response = {
        'access_token': token,
        'token_type': 'Bearer'
    }

    return response

@router_auth.get('/users/exists')
async def check_user_exists(
    name: str | None = Bind.i.query_n,
    email: str | None = Bind.i.query_n,
    phone: str | None = Bind.i.query_n,
    conn: Bind.Conn = Bind.conn.auth
) -> UserExists:
    """
    Check exists of user.

    Parameters
    ----------
    name : Check user name availability.
    email : Check email availability.
    phone : Check phone number availability.

    Returns
    -------
    User exists result.
    """

    # Parameter.
    sql_where_parts = []
    kwdata = {}
    if name is not None:
        sql_where_parts.append('"name" = :name')
        kwdata['name'] = name
    if email is not None:
        sql_where_parts.append('"email" = :email')
        kwdata['email'] = email
    if phone is not None:
        sql_where_parts.append('"phone" = :phone')
        kwdata['phone'] = phone
    if sql_where_parts == []:
        exit_api(text='At least one of parameter "name", "email", or "phone" must be provided.')

    # Select.
    sql_where = ' OR '.join(sql_where_parts)
    is_exists = await conn.execute.exist('user', sql_where, **kwdata)

    # Response.
    response = {'is_exists': is_exists}

    return response


@router_auth.get('/user')
async def get_user_info(
    user: Bind.User = Bind.user,
    sess: Bind.Sess = Bind.sess.auth
) -> DatabaseORMModelUserOut:
    """
    Get user information.

    Returns
    -------
    User information.
    """

    # Get.
    user = await sess.get(DatabaseORMTableUser, user.user_id)
    user_out = DatabaseORMModelUserOut.model_validate(user)

    return user_out

@router_auth.patch('/user/name')
async def update_user_name(
    name: str = Bind.i.body_k,
    user: Bind.User = Bind.user,
    sess: Bind.Sess = Bind.sess.auth
) -> None:
    """
    Update user name.

    Parameters
    ----------
    name : User name.
    """

    # Update.
    sql_where = f'"user_id" = "{user.user_id}"'
    await sess.update(DatabaseORMTableUser).values(name=name).where(sql_where).execute()

@router_auth.patch('/user/password')
async def update_user_password(
    password: str = Bind.i.body_k,
    new_password: str = Bind.i.body_k,
    user: Bind.User = Bind.user,
    conn: Bind.Conn = Bind.conn.auth,
    sess: Bind.Sess = Bind.sess.auth
) -> None:
    """
    Update user name.

    Parameters
    ----------
    password : User password.
    new_password : New user password.
    """

    # Check.
    user_data: User = await get_user_data(conn, user.user_id, 'user_id')
    if not is_hash_bcrypt(password, user_data['password']):
        exit_api(401)

    # Update.
    new_password = hash_bcrypt(new_password)
    sql_where = f'"user_id" = "{user.user_id}"'
    await sess.update(DatabaseORMTableUser).values(password=new_password).where(sql_where).execute()

@router_auth.patch('/user/email')
async def update_user_email(
    captcha: int = Bind.i.body_k,
    new_email: str = Bind.i.body_k,
    user: Bind.User = Bind.user,
    sess: Bind.Sess = Bind.sess.auth
) -> None:
    """
    Update user email.

    Parameters
    ----------
    captcha : Captcha.
    new_email : New user email.
    """

    # Check.
    ...

    # Update.
    sql_where = f'"user_id" = "{user.user_id}"'
    await sess.update(DatabaseORMTableUser).values(email=new_email).where(sql_where).execute()

@router_auth.patch('/user/phone')
async def update_user_phone(
    captcha: int = Bind.i.body_k,
    new_phone: str = Bind.i.body_k,
    user: Bind.User = Bind.user,
    sess: Bind.Sess = Bind.sess.auth
) -> None:
    """
    Update user phone number.

    Parameters
    ----------
    captcha : Captcha.
    new_phone : New user phone number.
    """

    # Check.
    ...

    # Update.
    sql_where = f'"user_id" = "{user.user_id}"'
    await sess.update(DatabaseORMTableUser).values(phone=new_phone).where(sql_where).execute()

@router_auth.patch('/user/avatar')
async def update_user_avatar(
    file: Bind.File = Bind.i.forms,
    user: Bind.User = Bind.user,
    sess: Bind.Sess = Bind.sess.auth
) -> DatabaseORMModelUserOut:
    """
    Update user phone number.

    Parameters
    ----------
    code : Verification code.
    new_phone : New user phone number.

    Returns
    -------
    User information.
    """

    # Upload.
    file_id = ...

    # Update.
    sql_where = f'"user_id" = "{user.user_id}"'
    await sess.update(DatabaseORMTableUser).values(avatar=file_id).where(sql_where).execute()
    await sess.commit()

    # Get.
    sess.get(DatabaseORMModelUserOut, user.user_id)

    return file_id
