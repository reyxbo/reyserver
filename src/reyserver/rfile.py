# !/usr/bin/env python
# -*- coding: utf-8 -*-

"""
@Time    : 2025-10-06
@Author  : Rey
@Contact : reyxbo@163.com
@Explain : File methods. Can create database used "self.build_db" function.
"""


from fastapi import APIRouter
from fastapi.responses import FileResponse
from reydb import rorm, DatabaseEngine, DatabaseEngineAsync
from reykit.ros import get_md5

from .rbase import exit_api
from .rbind import Bind
from .rcache import wrap_cache


__all__ = (
    'DatabaseORMTableInfo',
    'DatabaseORMTableData',
    'build_db_file',
    'router_file'
)


class DatabaseORMTableInfo(rorm.Table):
    """
    Database "info" table ORM model.
    """

    __name__ = 'info'
    __comment__ = 'File information table.'
    create_time: rorm.Datetime = rorm.Field(field_default=':time', not_null=True, index_n=True, comment='Record create time.')
    file_id: int = rorm.Field(key_auto=True, comment='File ID.')
    md5: str = rorm.Field(rorm.types.CHAR(32), not_null=True, index_n=True, comment='File MD5.')
    name: str = rorm.Field(rorm.types.VARCHAR(260), index_n=True, comment='File name.')
    note: str = rorm.Field(rorm.types.VARCHAR(500), comment='File note.')


class DatabaseORMTableData(rorm.Table):
    """
    Database "data" table ORM model.
    """

    __name__ = 'data'
    __comment__ = 'File data table.'
    md5: str = rorm.Field(rorm.types.CHAR(32), key=True, comment='File MD5.')
    size: int = rorm.Field(not_null=True, comment='File bytes size.')
    path: str = rorm.Field(rorm.types.VARCHAR(4095), not_null=True, comment='File disk storage relative path.')


def build_db_file(engine: DatabaseEngine | DatabaseEngineAsync) -> None:
    """
    Check and build "file" database tables.

    Parameters
    ----------
    db : Database engine instance.
    """

    # Set parameter.

    ## Table.
    tables = [DatabaseORMTableInfo, DatabaseORMTableData]

    ## View.
    views = [
        {
            'table': 'data_info',
            'select': (
                'SELECT "b"."last_time", "a"."md5", "a"."size", "b"."names", "b"."notes"\n'
                'FROM "data" AS "a"\n'
                'LEFT JOIN (\n'
                '    SELECT\n'
                '        "md5",\n'
                '        STRING_AGG(DISTINCT "name", \' | \') AS "names",\n'
                '        STRING_AGG(DISTINCT "note", \' | \') AS "notes",\n'
                '        MAX("create_time") as "last_time"\n'
                '    FROM (\n'
                '        SELECT "create_time", "md5", "name", "note"\n'
                '        FROM "info"\n'
                '        ORDER BY "create_time" DESC\n'
                '    ) AS "INFO"\n'
                '    GROUP BY "md5"\n'
                '    ORDER BY "last_time" DESC\n'
                ') AS "b"\n'
                'ON "a"."md5" = "b"."md5"\n'
                'ORDER BY "last_time" DESC'
            )
        }
    ]

    ## View stats.
    views_stats = [
        {
            'table': 'stats',
            'items': [
                {
                    'name': 'count',
                    'select': (
                        'SELECT COUNT(1)\n'
                        'FROM "info"'
                    ),
                    'comment': 'File information count.'
                },
                {
                    'name': 'past_day_count',
                    'select': (
                        'SELECT COUNT(1)\n'
                        'FROM "info"\n'
                        'WHERE DATE_PART(\'day\', NOW() - "create_time") = 0'
                    ),
                    'comment': 'File information count in the past day.'
                },
                {
                    'name': 'past_week_count',
                    'select': (
                        'SELECT COUNT(1)\n'
                        'FROM "info"\n'
                        'WHERE DATE_PART(\'day\', NOW() - "create_time") <= 6'
                    ),
                    'comment': 'File information count in the past week.'
                },
                {
                    'name': 'past_month_count',
                    'select': (
                        'SELECT COUNT(1)\n'
                        'FROM "info"\n'
                        'WHERE DATE_PART(\'day\', NOW() - "create_time") <= 29'
                    ),
                    'comment': 'File information count in the past month.'
                },
                {
                    'name': 'data_count',
                    'select': (
                        'SELECT COUNT(1)\n'
                        'FROM "data"'
                    ),
                    'comment': 'File data unique count.'
                },
                {
                    'name': 'total_size',
                    'select': (
                        'SELECT TO_CHAR(SUM("size"), \'FM999,999,999,999,999\')\n'
                        'FROM "data"'
                    ),
                    'comment': 'File total byte size.'
                },
                {
                    'name': 'avg_size',
                    'select': (
                        'SELECT TO_CHAR(ROUND(AVG("size")), \'FM999,999,999,999,999\')\n'
                        'FROM "data"'
                    ),
                    'comment': 'File average byte size.'
                },
                {
                    'name': 'max_size',
                    'select': (
                        'SELECT TO_CHAR(MAX("size"), \'FM999,999,999,999,999\')\n'
                        'FROM "data"'
                    ),
                    'comment': 'File maximum byte size.'
                },
                {
                    'name': 'last_time',
                    'select': (
                        'SELECT MAX("create_time")\n'
                        'FROM "info"'
                    ),
                    'comment': 'File last record create time.'
                }
            ]
        }
    ]

    # Build.
    engine.sync_engine.build.build(tables=tables, views=views, views_stats=views_stats, skip=True)


router_file = APIRouter()


@router_file.get('/files/{file_id}')
@wrap_cache
async def get_file_info(
    file_id: int = Bind.i.path,
    sess: Bind.Sess = Bind.sess.file
) -> DatabaseORMTableInfo:
    """
    Get file information.

    Parameters
    ----------
    file_id : File ID.

    Returns
    -------
    File information.
    """

    # Get.
    table_info = await sess.get(DatabaseORMTableInfo, file_id)

    # Check.
    if table_info is None:
        exit_api(404)

    return table_info


@router_file.post('/files')
async def upload_file(
    file: Bind.File = Bind.i.forms,
    name: str = Bind.i.forms_n,
    note: str = Bind.i.forms_n,
    sess: Bind.Sess = Bind.sess.file,
    server: Bind.Server = Bind.server
) -> DatabaseORMTableInfo:
    """
    Upload file.

    Parameters
    ----------
    file : File instance.
    name : File name.
    note : File note.

    Returns
    -------
    File information.
    """

    # Parameter.
    file_store = server.api_file_store
    file_bytes = await file.read()
    file_md5 = get_md5(file_bytes)
    file_size = len(file_bytes)

    # Upload.
    file_path = file_store.index(file_md5)

    ## Data.
    if file_path is None:
        file_path = file_store.store(file_bytes)
        file_relpath = file_store.get_relpath(file_path)
        table_data = DatabaseORMTableData(
            md5=file_md5,
            size=file_size,
            path=file_relpath
        )
        await sess.add(table_data)

    ## Information.
    table_info = DatabaseORMTableInfo(
        md5=file_md5,
        name=name,
        note=note
    )
    await sess.add(table_info)

    # Get ID.
    await sess.flush()

    return table_info


@router_file.get('/files/{file_id}/download')
async def download_file(
    file_id: int = Bind.i.path,
    conn: Bind.Conn = Bind.conn.file,
    server: Bind.Server = Bind.server
) -> FileResponse:
    """
    Download file.

    Parameters
    ----------
    file_id : File ID.

    Returns
    -------
    File data.
    """

    # Parameter.
    file_store = server.api_file_store

    # Search.
    sql = (
        'SELECT "name", (\n'
        '    SELECT "path"\n'
        '    FROM "data"\n'
        '    WHERE "md5" = "info"."md5"\n'
        '    LIMIT 1\n'
        ') AS "path"\n'
        'FROM "info"\n'
        'WHERE "file_id" = :file_id\n'
        'LIMIT 1'
    )
    result = await conn.execute(sql, file_id=file_id)

    # Check.
    if result.empty:
        exit_api(404)

    # Response.
    file_name, file_relpath = result.first()
    file_abspath = file_store.get_abspath(file_relpath)
    response = FileResponse(file_abspath, filename=file_name)

    return response
