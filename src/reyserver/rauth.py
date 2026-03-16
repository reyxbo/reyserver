# !/usr/bin/env python
# -*- coding: utf-8 -*-

"""
@Time    : 2025-10-10
@Author  : Rey
@Contact : reyxbo@163.com
@Explain : Authentication methods.
"""

from typing import Any, TypedDict, NotRequired, Literal
from datetime import datetime as Datetime, timedelta as Timedelta
from fastapi import APIRouter
from reyclient.rali import ClientAliVerifySms
from reydb import rorm, DatabaseEngine, DatabaseEngineAsync
from reykit.rbase import throw
from reykit.rdata import encode_jwt, hash_bcrypt, is_hash_bcrypt
from reykit.remail import Email
from reykit.rrand import randchar
from reykit.rre import PATTERN_EMAIL, PATTERN_PHONE, search
from reykit.rtime import now

from .rbase import ServerBase, exit_api
from .rbind import Bind

__all__ = (
    'DatabaseORMTableUser',
    'DatabaseORMTableRole',
    'DatabaseORMTablePerm',
    'DatabaseORMTableUserRole',
    'DatabaseORMTableRolePerm',
    'DatabaseORMTableVerifyEmail',
    'DatabaseORMModelUserOut',
    'ServerVerifyEmail',
    'build_db_auth',
    'router_auth'
)

UserData = TypedDict(
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
'User data dictionary.'
Token = TypedDict(
    'Token',
    {
        'sub': str,
        'iat': int,
        'nbf': int,
        'exp': int,
        'user_id': int,
        'perm_apis': list[str]
    }
)
'Token data dictionary.'
type TokenStr = str
'Token string.'
JSONToken = TypedDict(
    'JSONToken',
    {
        'access_token': TokenStr,
        'token_type': Literal['Bearer']
    }
)
'JSON dictionary with Token string.'
type VerificationScenes = Literal['token', 'signup', 'reset']
'Verification scene range.'

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
    email: rorm.Email | None = rorm.Field(rorm.types.VARCHAR(255), index_u=True, comment='User email.')
    phone: str | None = rorm.Field(rorm.types.CHAR(11), index_u=True, comment=f'User phone.', re=PATTERN_PHONE)
    avatar: int | None = rorm.Field(comment='User avatar file ID.')
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
    desc: str | None = rorm.Field(rorm.types.VARCHAR(500), comment='Role description.')
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
    desc: str | None = rorm.Field(rorm.types.VARCHAR(500), comment='Permission description.')
    api: str | None = rorm.Field(
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

class DatabaseORMTableVerifyEmail(rorm.Table):
    """
    Database `verify_email` table ORM model.
    """

    __name__ = 'verify_email'
    __comment__ = 'Verify email record table.'
    id: int = rorm.Field(key_auto=True, comment='ID.')
    send_time: rorm.Datetime = rorm.Field(field_default=':time', not_null=True, index_n=True, comment='Send time.')
    use_time: rorm.Datetime | None = rorm.Field(comment='Use time.')
    expire_time: rorm.Datetime = rorm.Field(not_null=True, index_n=True, comment='Expire time.')
    scene: str = rorm.Field(rorm.types.VARCHAR(20), not_null=True, index_n=True, comment='Usage scene.')
    email: rorm.Email = rorm.Field(not_null=True, index_n=True, comment='Verification email.')
    code: str = rorm.Field(rorm.types.VARCHAR(8), not_null=True, index_n=True, comment='Verification code.', len_min=4, len_max=8)
    verify_count: int = rorm.Field(rorm.types.SMALLINT, field_default='0', not_null=True, comment='Verify count.')
    used: bool = rorm.Field(field_default='FALSE', not_null=True, comment='Is the used.')

class DatabaseORMTableVerifyPhone(rorm.Table):
    """
    Database `verify_phone` table ORM model.
    """

    __name__ = 'verify_phone'
    __comment__ = 'Verify phone record table.'
    id: int = rorm.Field(key_auto=True, comment='ID.')
    send_time: rorm.Datetime = rorm.Field(field_default=':time', not_null=True, index_n=True, comment='Send time.')
    use_time: rorm.Datetime | None = rorm.Field(comment='Use time.')
    expire_time: rorm.Datetime = rorm.Field(not_null=True, index_n=True, comment='Expire time.')
    scene: str = rorm.Field(rorm.types.VARCHAR(20), not_null=True, index_n=True, comment='Usage scene.')
    phone: str = rorm.Field(rorm.types.CHAR(11), not_null=True, index_n=True, comment=f'Verification phone.', re=PATTERN_PHONE)
    code: str = rorm.Field(rorm.types.VARCHAR(8), not_null=True, index_n=True, comment='Verification code.', len_min=4, len_max=8)
    verify_count: int = rorm.Field(rorm.types.SMALLINT, field_default='0', not_null=True, comment='Verify count.')
    used: bool = rorm.Field(field_default='FALSE', not_null=True, comment='Is the used.')

class DatabaseORMModelUserInput(rorm.Model):
    """
    Database input user ORM model.
    """

    name: str = rorm.Field(rorm.types.VARCHAR(50), not_null=True, comment=f'User name.', len_min=3)
    password: str = rorm.Field(rorm.types.CHAR(60), not_null=True, comment='User password, encrypted with "bcrypt".', len_min=6)
    email: rorm.Email | None = rorm.Field(rorm.types.VARCHAR(255), comment='User email, must with parameter "email_code".')
    email_code: str | None = rorm.Field(rorm.types.VARCHAR(8), comment='Email verification code.', len_min=4, len_max=8)
    phone: str | None = rorm.Field(rorm.types.CHAR(11), comment=f'User phone, must with parameter "phone_code".', re=PATTERN_PHONE)
    phone_code: str | None = rorm.Field(rorm.types.VARCHAR(8), comment='Phone verification code.', len_min=4, len_max=8)

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

class DatabaseORMModelUserOut(rorm.Model):
    """
    Database out user ORM model.
    """

    create_time: rorm.Datetime | None = rorm.Field(comment='Record create time.')
    update_time: rorm.Datetime | None = rorm.Field( comment='Record update time.')
    user_id: int | None = rorm.Field(comment='User ID.')
    name: str = rorm.Field(rorm.types.VARCHAR(50), not_null=True, comment=f'User name.', len_min=3)
    email: rorm.Email | None = rorm.Field(comment='User email.')
    phone: str | None = rorm.Field(rorm.types.CHAR(11), comment=f'User phone.', re=PATTERN_PHONE)
    avatar: int | None = rorm.Field(comment='User avatar file ID.')

class ServerVerifyEmail(ServerBase):
    """
    Server verify email type.
    Can create database used "self.build_db" method.
    """

    def __init__(
        self,
        client: Email,
        db_engine: DatabaseEngine | DatabaseEngineAsync,
        title: str,
        text_format: str,
        code_len=4,
        valid_m: int = 5,
        interval_s: int = 60,
        max_attempts: int =  5
    ) -> None:
        """
        Build instance attributes.

        Parameters
        ----------
        email : Email client instance.
        db_engine : Database engine, insert request record to table.
        title: Send email title.
        text_format : Send email text format, use `{code}` replace random verification code, use `{min}` replace valid minutes.
        code_len : Code length, [4-8].
        valid_m : Code valid minutes.
        interval_s : Resend interval seconds.
        max_attempts : Maximum number of attempts, add 1 on error.
        """

        # Set attribute.
        self.client = client
        self.db_engine = db_engine
        self.title = title
        self.text_format = text_format
        self.code_len = code_len
        self.valid_m = valid_m
        self.interval_s = interval_s
        self.max_attempts = max_attempts

        # Database.
        self.build_db()

    def send(self, scene: str, email: str) -> str:
        """
        Send email with random verification code.

        Parameters
        ----------
        scene : Usage scene, maxinunMaximum 20 characters.
        email : Email address.

        Returns
        -------
        Verification code.
        """

        # Parameter.
        db_engine = self.db_engine.sync_engine

        # Check.
        sql_where = (
            f'"send_time" > NOW() - interval \'{self.interval_s} second\' AND "email" = :email AND "scene" = :scene'
        )
        is_exists = db_engine.execute.exist(
            'verify_email',
            sql_where,
            email=email,
            scene=scene
        )
        if is_exists:
            throw(AssertionError, text='interval time not elapsed')

        # Send.
        code = randchar(self.code_len, 'd')
        text = self.text_format.format(code=code, min=self.valid_m)
        self.client.send_email(
            email,
            self.title,
            text
        )

        # Database.
        data = {
            'expire_time': now('datetime') + Timedelta(minutes=self.valid_m),
            'scene': scene,
            'email': email,
            'code': code
        }
        db_engine.execute.insert('verify_email', data)

        return code

    async def async_send(self, scene: str, email: str) -> str:
        """
        Asynchronous send email with random verification code.

        Parameters
        ----------
        scene : Usage scene, maxinunMaximum 20 characters.
        email : Email address.

        Returns
        -------
        Verification code.
        """

        # Parameter.
        db_engine = self.db_engine.async_engine

        # Check.
        sql_where = (
            f'"send_time" > NOW() - interval \'{self.interval_s} second\' AND "email" = :email AND "scene" = :scene'
        )
        is_exists = await db_engine.execute.exist(
            'verify_email',
            sql_where,
            email=email,
            scene=scene
        )
        if is_exists:
            throw(AssertionError, text='interval time not elapsed')

        # Send.
        code = randchar(self.code_len, 'd')
        text = self.text_format.format(code=code, min=self.valid_m)
        self.client.send_email(
            email,
            self.title,
            text
        )

        # Database.
        data = {
            'expire_time': now('datetime') + Timedelta(minutes=self.valid_m),
            'scene': scene,
            'email': email,
            'code': code
        }
        await db_engine.execute.insert('verify_email', data)

        return code

    def verify(self, scene: str, email: str, code: str, use: bool = False) -> bool:
        """
        Verify code.

        Parameters
        ----------
        scene : Usage scene, maxinunMaximum 20 characters.
        email : Email address.
        code : Verification code.
        use : Whether to use up.

        Returns
        -------
        Verify result.
        """

        # Parameter.
        db_engine = self.db_engine.sync_engine
        with db_engine.connect() as conn:

            # Select.
            sql_where = (
                '(\n'
                '    "expire_time" > NOW()\n'
                '    AND "used" = FALSE\n'
                '    AND "email" = :email\n'
                '    AND "scene" = :scene\n'
                '    AND "verify_count" <= :max_attempts\n'
                ')\n'
            )
            sql_order = '"send_time" DESC'
            result = conn.execute.select(
                'verify_email',
                ('id', 'code', 'verify_count'),
                sql_where,
                order=sql_order,
                limit=1,
                email=email,
                scene=scene,
                max_attempts=self.max_attempts
            )
            row = result.first()

            # Empty.
            if row is None:
                return False

            # Success.
            verify_id, correct_code, verify_count = row
            if correct_code == code:
                if use:
                    data = {'id': verify_id, 'use_time': ':NOW():', 'used': True}
                    conn.execute.update('verify_email', data)
                return True

            # Fail.
            else:
                data = {'id': verify_id, 'verify_count': verify_count + 1}
                conn.execute.update('verify_email', data)
                return False

    async def async_verify(self, scene: VerificationScenes, email: str, code: str, use: bool = False) -> bool:
        """
        Asynchronous verify code.

        Parameters
        ----------
        scene : Usage scene, maxinunMaximum 20 characters.
        email : Email address.
        code : Verification code.
        use : Whether to use up.

        Returns
        -------
        Verify result.
        """

        # Parameter.
        db_engine = self.db_engine.async_engine
        async with db_engine.connect() as conn:

            # Select.
            sql_where = (
                '(\n'
                '    "expire_time" > NOW()\n'
                '    AND "used" = FALSE\n'
                '    AND "email" = :email\n'
                '    AND "scene" = :scene\n'
                '    AND "verify_count" <= :max_attempts\n'
                ')\n'
            )
            sql_order = '"send_time" DESC'
            result = await conn.execute.select(
                'verify_email',
                ('id', 'code', 'verify_count'),
                sql_where,
                order=sql_order,
                limit=1,
                email=email,
                scene=scene,
                max_attempts=self.max_attempts
            )
            row = result.first()

            # Empty.
            if row is None:
                return False

            # Success.
            verify_id, correct_code, verify_count = row
            if correct_code == code:
                if use:
                    data = {'id': verify_id, 'use_time': ':NOW():', 'used': True}
                    await conn.execute.update('verify_email', data)
                return True

            # Fail.
            else:
                data = {'id': verify_id, 'verify_count': verify_count + 1}
                await conn.execute.update('verify_email', data)
                return False

    def build_db(self) -> None:
        """
        Check and build database tables.
        """

        # Parameter.

        ## Table.
        tables = [DatabaseORMTableVerifyEmail]

        ## View stats.
        views_stats = [
            {
            'table': 'stats_verify_email',
            'items': [
                {
                    'name': 'count',
                    'select': (
                        'SELECT COUNT(1)\n'
                        'FROM "verify_email"'
                    ),
                    'comment': 'Send count.'
                },
                {
                    'name': 'past_day_count',
                    'select': (
                        'SELECT COUNT(1)\n'
                        'FROM "verify_email"'
                        'WHERE DATE_PART(\'day\', NOW() - "send_time") = 0'
                    ),
                    'comment': 'Send count in the past day.'
                },
                {
                    'name': 'past_week_count',
                    'select': (
                        'SELECT COUNT(1)\n'
                        'FROM "verify_email"'
                        'WHERE DATE_PART(\'day\', NOW() - "send_time") <= 6'
                    ),
                    'comment': 'Send count in the past week.'
                },
                {
                    'name': 'past_month_count',
                    'select': (
                        'SELECT COUNT(1)\n'
                        'FROM "verify_email"'
                        'WHERE DATE_PART(\'day\', NOW() - "send_time") <= 29'
                    ),
                    'comment': 'Send count in the past month.'
                }
            ]
        }
        ]

        # Build.
        self.db_engine.sync_engine.build(tables=tables, views_stats=views_stats, skip=True)

class ServerVerifyPhone(ServerBase):
    """
    Server verify phone type.
    Can create database used "self.build_db" method.
    """

    def __init__(
        self,
        client: ClientAliVerifySms,
        db_engine: DatabaseEngine | DatabaseEngineAsync,
        valid_m: int = 5,
        interval_s: int = 60,
        max_attempts: int =  5
    ) -> None:
        """
        Build instance attributes.

        Parameters
        ----------
        email : Phone client instance.
        db_engine : Database engine, insert request record to table.
        valid_m : Code valid minutes.
        interval_s : Resend interval seconds.
        max_attempts : Maximum number of attempts, add 1 on error.
        """

        # Set attribute.
        self.client = client
        self.db_engine = db_engine
        self.valid_m = valid_m
        self.interval_s = interval_s
        self.max_attempts = max_attempts

        # Database.
        self.build_db()

    def send(self, scene: str, phone: str) -> str:
        """
        Send sms with random verification code.

        Parameters
        ----------
        scene : Usage scene, maxinunMaximum 20 characters.
        phone : Phone number.

        Returns
        -------
        Verification code.
        """

        # Parameter.
        db_engine = self.db_engine.sync_engine

        # Check.
        sql_where = (
            f'"send_time" > NOW() - interval \'{self.interval_s} second\' AND "phone" = :phone AND "scene" = :scene'
        )
        is_exists = db_engine.execute.exist(
            'verify_phone',
            sql_where,
            phone=phone,
            scene=scene
        )
        if is_exists:
            throw(AssertionError, text='interval time not elapsed')

        # Send.
        code = self.client.send(
            scene,
            phone,
        )

        # Database.
        data = {
            'expire_time': now('datetime') + Timedelta(minutes=self.valid_m),
            'scene': scene,
            'phone': phone,
            'code': code
        }
        db_engine.execute.insert('verify_phone', data)

        return code

    async def async_send(self, scene: str, phone: str) -> str:
        """
        Asynchronous send sms with random verification code.

        Parameters
        ----------
        scene : Usage scene, maxinunMaximum 20 characters.
        phone : Phone number.

        Returns
        -------
        Verification code.
        """

        # Parameter.
        db_engine = self.db_engine.async_engine

        # Check.
        sql_where = (
            f'"send_time" > NOW() - interval \'{self.interval_s} second\' AND "phone" = :phone AND "scene" = :scene'
        )
        is_exists = await db_engine.execute.exist(
            'verify_phone',
            sql_where,
            phone=phone,
            scene=scene
        )
        if is_exists:
            throw(AssertionError, text='interval time not elapsed')

        # Send.
        code = await self.client.async_send(
            scene,
            phone,
        )

        # Database.
        data = {
            'expire_time': now('datetime') + Timedelta(minutes=self.valid_m),
            'scene': scene,
            'phone': phone,
            'code': code
        }
        await db_engine.execute.insert('verify_phone', data)

        return code

    def verify(self, scene: str, phone: str, code: str, use: bool = False) -> bool:
        """
        Verify code.

        Parameters
        ----------
        scene : Usage scene, maxinunMaximum 20 characters.
        phone : Phone number.
        code : Verification code.
        use : Whether to use up.

        Returns
        -------
        Verify result.
        """

        # Parameter.
        db_engine = self.db_engine.sync_engine
        with db_engine.connect() as conn:

            # Select.
            sql_where = (
                '(\n'
                '    "expire_time" > NOW()\n'
                '    AND "used" = FALSE\n'
                '    AND "phone" = :phone\n'
                '    AND "scene" = :scene\n'
                '    AND "verify_count" <= :max_attempts\n'
                ')\n'
            )
            sql_order = '"send_time" DESC'
            result = conn.execute.select(
                'verify_phone',
                ('id', 'code', 'verify_count'),
                sql_where,
                order=sql_order,
                limit=1,
                phone=phone,
                scene=scene,
                max_attempts=self.max_attempts
            )
            row = result.first()

            # Empty.
            if row is None:
                return False

            # Success.
            verify_id, correct_code, verify_count = row
            if correct_code == code:
                if use:
                    data = {'id': verify_id, 'use_time': ':NOW():', 'used': True}
                    conn.execute.update('verify_phone', data)
                return True

            # Fail.
            else:
                data = {'id': verify_id, 'verify_count': verify_count + 1}
                conn.execute.update('verify_phone', data)
                return False

    async def async_verify(self, scene: str, phone: str, code: str, use: bool = False) -> bool:
        """
        Asynchronous verify code.

        Parameters
        ----------
        scene : Usage scene, maxinunMaximum 20 characters.
        phone : Phone number.
        code : Verification code.
        use : Whether to use up.

        Returns
        -------
        Verify result.
        """

        # Parameter.
        db_engine = self.db_engine.async_engine
        async with db_engine.connect() as conn:

            # Select.
            sql_where = (
                '(\n'
                '    "expire_time" > NOW()\n'
                '    AND "used" = FALSE\n'
                '    AND "phone" = :phone\n'
                '    AND "scene" = :scene\n'
                '    AND "verify_count" <= :max_attempts\n'
                ')\n'
            )
            sql_order = '"send_time" DESC'
            result = await conn.execute.select(
                'verify_phone',
                ('id', 'code', 'verify_count'),
                sql_where,
                order=sql_order,
                limit=1,
                phone=phone,
                scene=scene,
                max_attempts=self.max_attempts
            )
            row = result.first()

            # Empty.
            if row is None:
                return False

            # Success.
            verify_id, correct_code, verify_count = row
            if correct_code == code:
                if use:
                    data = {'id': verify_id, 'use_time': ':NOW():', 'used': True}
                    await conn.execute.update('verify_phone', data)
                return True

            # Fail.
            else:
                data = {'id': verify_id, 'verify_count': verify_count + 1}
                await conn.execute.update('verify_phone', data)
                return False

    def build_db(self) -> None:
        """
        Check and build database tables.
        """

        # Parameter.

        ## Table.
        tables = [DatabaseORMTableVerifyPhone]

        ## View stats.
        views_stats = [
            {
            'table': 'stats_verify_phone',
            'items': [
                {
                    'name': 'count',
                    'select': (
                        'SELECT COUNT(1)\n'
                        'FROM "verify_phone"'
                    ),
                    'comment': 'Send count.'
                },
                {
                    'name': 'past_day_count',
                    'select': (
                        'SELECT COUNT(1)\n'
                        'FROM "verify_phone"'
                        'WHERE DATE_PART(\'day\', NOW() - "send_time") = 0'
                    ),
                    'comment': 'Send count in the past day.'
                },
                {
                    'name': 'past_week_count',
                    'select': (
                        'SELECT COUNT(1)\n'
                        'FROM "verify_phone"'
                        'WHERE DATE_PART(\'day\', NOW() - "send_time") <= 6'
                    ),
                    'comment': 'Send count in the past week.'
                },
                {
                    'name': 'past_month_count',
                    'select': (
                        'SELECT COUNT(1)\n'
                        'FROM "verify_phone"'
                        'WHERE DATE_PART(\'day\', NOW() - "send_time") <= 29'
                    ),
                    'comment': 'Send count in the past month.'
                }
            ]
        }
        ]

        # Build.
        self.db_engine.sync_engine.build(tables=tables, views_stats=views_stats, skip=True)

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
    engine.sync_engine.build(tables=tables, views_stats=views_stats, skip=True)

router_auth = APIRouter()

def get_account_type(account: str) -> Literal['name', 'email', 'phone']:
    """
    Judge account type.

    Parameters
    ----------
    account : User account, user name or email address or phone number.

    Returns
    -------
    Account type.
    """

    # Judge.
    if search(PATTERN_EMAIL, account) is not None:
        account_type = 'email'
    elif search(PATTERN_PHONE, account) is not None:
        account_type = 'phone'
    else:
        account_type = 'name'

    return account_type

async def get_user_data(
    conn: Bind.Conn,
    index: str | int,
    index_type: Literal['user_id', 'name', 'email', 'phone', 'account'],
    filter_invalid: bool = True
) -> UserData | None:
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
    if index_type == 'account':
        index_type = get_account_type(index)
    if filter_invalid:
        sql_where_user = (
            '    WHERE (\n'
            f'        "{index_type}" = :index\n'
            '        AND "is_valid" = TRUE\n'
            '    )\n'
        )
        sql_where_role = sql_where_perm = '    WHERE "is_valid" = TRUE\n'
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
        info: UserData = {
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
    data: UserData,
    key: str,
    seconds: int
) -> TokenStr:
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
    json: Token = {
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
    grant_type: Literal['password', 'email_code', 'phone_code'] = Bind.i.form,
    username: str = Bind.i.form,
    password: str = Bind.i.form,
    conn: Bind.Conn = Bind.conn.auth,
    server: Bind.Server = Bind.server
) -> JSONToken:
    """
    Get token.

    Parameters
    ----------
    grant_type : Grant type.
        - `Literal['password']`: Use `name+password` or `email+password` or `phone+password`.
        - `Literal['email_code']`: Use `email+code`.
        - `Literal['phone_code']`: Use `phone+code`.
    username : User name or email or phone number.
    password : User password or verification code.

    Returns
    -------
    JSON with "token".
    """

    # Check.

    ## Name.
    if grant_type == 'password':
        user_data = await get_user_data(conn, username, 'account')
        if (
            user_data is None
            or not is_hash_bcrypt(password, user_data['password'])
        ):
            exit_api(401)

    ## Email.
    if grant_type == 'email_code':
        client_email = server.api_auth_client_email
        result = await client_email.async_verify('token', username, password, True)
        if not result:
            exit_api(401)
        user_data = await get_user_data(conn, username, 'email')
        if user_data is None:
            exit_api(401)

    ## Sms.
    if grant_type == 'phone_code':
        client_phone = server.api_auth_client_phone
        result = await client_phone.async_verify('token', username, password)
        if not result:
            exit_api(401)
        user_data = await get_user_data(conn, username, 'phone')
        if user_data is None:
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
    model_user: DatabaseORMModelUserInput,
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

    # Parameter.
    init_role_id = server.api_auth_init_role_id
    client_email = server.api_auth_client_email
    client_phone = server.api_auth_client_phone

    # Verify.
    if model_user.email is not None:
        if model_user.email_code is None:
            exit_api(text='missing parameter "email_code"')
        else:
            result = await client_email.async_verify(
                'signup',
                model_user.email,
                model_user.email_code,
                True
            )
            if not result:
                exit_api(text='parameter "email_code" verification failed')
    if model_user.phone is not None:
        if model_user.phone_code is None:
            exit_api(text='missing parameter "phone_code"')
        else:
            result = await client_phone.async_verify(
                'signup',
                model_user.phone,
                model_user.phone_code,
                True
            )
            if not result:
                exit_api(text='parameter "phone_code" verification failed')

    # Signup.
    update = {'password': hash_bcrypt(model_user.password).decode()}
    table_user = DatabaseORMTableUser.model_validate(model_user, update=update)
    await sess.add(table_user)
    await sess.flush()
    user_role = DatabaseORMTableUserRole(
        user_id=table_user.user_id,
        role_id=init_role_id
    )
    await sess.add(user_role)
    user_id = table_user.user_id
    await sess.commit()

    # Token.
    user_data: UserData = await get_user_data(conn, user_id, 'user_id')
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
) -> bool:
    """
    Check exists of user.

    Parameters
    ----------
    name : Check user name availability.
    email : Check email availability.
    phone : Check phone number availability.

    Returns
    -------
    Result.
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

    return is_exists

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
    user_data: UserData = await get_user_data(conn, user.user_id, 'user_id')
    if not is_hash_bcrypt(password, user_data['password']):
        exit_api(401)

    # Update.
    new_password = hash_bcrypt(new_password)
    sql_where = f'"user_id" = "{user.user_id}"'
    await sess.update(DatabaseORMTableUser).values(password=new_password).where(sql_where).execute()

@router_auth.patch('/user/email')
async def update_user_email(
    new_email: str = Bind.i.body_k,
    code: int = Bind.i.body_k,
    user: Bind.User = Bind.user,
    sess: Bind.Sess = Bind.sess.auth,
    server: Bind.Server = Bind.server
) -> None:
    """
    Update user email.

    Parameters
    ----------
    new_email : New user email.
    code : Email verification code.
    """

    # Parmeter.
    client_email = server.api_auth_client_email

    # Check.
    result = await client_email.async_verify('reset', new_email, code, True)
    if not result:
        exit_api(text='parameter "code" verification failed')

    # Update.
    sql_where = f'"user_id" = "{user.user_id}"'
    await sess.update(DatabaseORMTableUser).values(email=new_email).where(sql_where).execute()

@router_auth.patch('/user/phone')
async def update_user_phone(
    new_phone: str = Bind.i.body_k,
    code: int = Bind.i.body_k,
    user: Bind.User = Bind.user,
    sess: Bind.Sess = Bind.sess.auth,
    server: Bind.Server = Bind.server
) -> None:
    """
    Update user phone number.

    Parameters
    ----------
    new_phone : New user phone number.
    code : Sms verification code.
    """

    # Parmeter.
    client_phone = server.api_auth_client_phone

    # Check.
    result = await client_phone.async_verify('reset', new_phone, code, True)
    if not result:
        exit_api(text='parameter "code" verification failed')

    # Update.
    sql_where = f'"user_id" = "{user.user_id}"'
    await sess.update(DatabaseORMTableUser).values(phone=new_phone).where(sql_where).execute()

@router_auth.patch('/user/avatar')
async def update_user_avatar(
    file_models: Bind.FileModels = Bind.file,
    user: Bind.User = Bind.user,
    sess: Bind.Sess = Bind.sess.auth
) -> int:
    """
    Update user phone number.

    Returns
    -------
    Avatar file ID.
    """

    # Parameter.
    model_file_info = file_models[0]
    file_id = model_file_info.file_id

    # Update.
    sql_where = f'"user_id" = "{user.user_id}"'
    await sess.update(DatabaseORMTableUser).values(avatar=file_id).where(sql_where).execute()
    await sess.commit()

    return file_id

@router_auth.post('/email-codes')
async def send_email_code(
    scene: VerificationScenes = Bind.Body(max_length=20),
    email: Bind.Email = Bind.i.body,
    server: Bind.Server = Bind.server
) -> None:
    """
    Send email verification code.

    Parameters
    ----------
    scene : Usage scene.
    email : Email address.
    """

    # Parameter.
    client_email = server.api_auth_client_email

    # Check.
    is_exists = await check_user_exists(email=email)
    if not is_exists:
        exit_api(404, text='user email address not exists')

    # Send.
    await client_email.async_send(scene, email)

@router_auth.post('/phone-codes')
async def send_phone_code(
    scene: VerificationScenes = Bind.Body(max_length=20),
    phone: str = Bind.i.body,
    server: Bind.Server = Bind.server
) -> None:
    """
    Send phone verification code.

    Parameters
    ----------
    scene : Usage scene.
    phone : Phone number.
    """

    # Parameter.
    client_sms = server.api_auth_client_phone

    # Check.
    is_exists = await check_user_exists(phone=phone)
    if not is_exists:
        exit_api(404, text='user phone number not exists')

    # Send.
    await client_sms.async_send(scene, phone)

@router_auth.post('/email_codes/verify')
async def verify_email_code(
    scene: VerificationScenes = Bind.Body(max_length=20),
    email: Bind.Email = Bind.i.body,
    code: str = Bind.Body(min_length=4, max_length=8),
    server: Bind.Server = Bind.server
) -> bool:
    """
    Verify email verification code.

    Parameters
    ----------
    scene : Usage scene.
    email : Email address.
    code : Verification code.

    Returns
    -------
    Result.
    """

    # Parmeter.
    client_email = server.api_auth_client_email

    # Verify.
    result = await client_email.async_verify(scene, email, code)

    return result

@router_auth.post('/phone_codes/verify')
async def verify_phone_code(
    scene: VerificationScenes = Bind.Body(max_length=20),
    phone: str = Bind.i.body,
    code: str = Bind.Body(min_length=4, max_length=8),
    server: Bind.Server = Bind.server
) -> bool:
    """
    Verify phone verification code.

    Parameters
    ----------
    scene : Usage scene.
    phone : Phone number.
    code : Verification code.

    Returns
    -------
    Result.
    """

    # Parmeter.
    client_phone = server.api_auth_client_phone

    # Verify.
    result = await client_phone.async_verify(scene, phone, code)

    return result
