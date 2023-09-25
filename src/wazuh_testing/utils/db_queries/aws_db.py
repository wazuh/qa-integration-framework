import sqlite3

# Local imports
from wazuh_testing.utils.database import get_sqlite_query_result, get_sqlite_fetch_one_query_result
from wazuh_testing.modules.aws.data_structures import s3_rows_map, service_rows_map, S3CloudTrailRow, \
    ServiceCloudWatchRow
from wazuh_testing.constants.aws import SELECT_QUERY_TEMPLATE
from wazuh_testing.constants.paths.aws import S3_CLOUDTRAIL_DB_PATH, AWS_SERVICES_DB_PATH

""" Database AWS utils"""


def _get_s3_row_type(bucket_type):
    """Get row type for bucket integration.

    Args:
        bucket_type (str): The name of the bucket.

    Returns:
        Type[S3CloudTrailRow]: The type that match or a default one.
    """
    return s3_rows_map.get(bucket_type, S3CloudTrailRow)


def _get_service_row_type(table_name):
    """Get row type for service integration.

    Args:
        table_name (str): Table name to match.

    Returns:
        Type[ServiceCloudWatchRow]: The type that match or a default one.
    """
    return service_rows_map.get(table_name, ServiceCloudWatchRow)


"""Database queries"""


# cloudtrail.db utils
def get_s3_db_row(table_name) -> S3CloudTrailRow:
    """Return one row from the given table name.

    Args:
        table_name (str): Table name to search into.

    Returns:
        S3CloudTrailRow: The first row of the table.
    """
    row_type = _get_s3_row_type(table_name)
    query = SELECT_QUERY_TEMPLATE.format(table_name=table_name)
    row = get_sqlite_fetch_one_query_result(S3_CLOUDTRAIL_DB_PATH, query)

    return row_type(*row)


def get_multiple_s3_db_row(table_name):
    """Return all rows from the given table name.

    Args:
        table_name (str): Table name to search into.

    Yields:
        Iterator[S3CloudTrailRow]: All the rows in the table.
    """
    row_type = _get_s3_row_type(table_name)
    query = SELECT_QUERY_TEMPLATE.format(table_name=table_name)
    rows = get_sqlite_query_result(S3_CLOUDTRAIL_DB_PATH, query)

    for row in rows:
        yield row_type(*row)


def table_exists(table_name, db_path=S3_CLOUDTRAIL_DB_PATH):
    """Check if the given table name exists.

    Args:
        table_name (str): Table name to search for.
        db_path (str, optional): Path to the SQLite database. Defaults to S3_CLOUDTRAIL_DB_PATH.

    Returns:
        bool: True if exists else False.
    """
    query = """
            SELECT
                name
            FROM
                sqlite_master
            WHERE
                type ='table' AND
                name NOT LIKE 'sqlite_%';
            """
    results = get_sqlite_query_result(db_path, query)

    return table_name in [result[0] for result in results]


def table_exists_or_has_values(table_name, db_path=S3_CLOUDTRAIL_DB_PATH):
    """Check if the given table name exists. If exists check if it has values.

    Args:
        table_name (str): Table name to search for.
        db_path (str, optional): Path to the SQLite database. Defaults to S3_CLOUDTRAIL_DB_PATH.

    Returns:
        bool: True if exists or has values else False.
    """
    try:
        query = SELECT_QUERY_TEMPLATE.format(table_name=table_name)
        result = get_sqlite_query_result(S3_CLOUDTRAIL_DB_PATH, query)
        return bool(result)
    except sqlite3.OperationalError:
        return False


# aws_services.db utils

def get_service_db_row(table_name):
    """Return one row from the given table name.

    Args:
        table_name (str): Table name to search into.

    Returns:
        ServiceInspectorRow: The first row of the table.
    """
    row_type = _get_service_row_type(table_name)

    query = SELECT_QUERY_TEMPLATE.format(table_name=table_name)
    row = get_sqlite_fetch_one_query_result(AWS_SERVICES_DB_PATH, query)

    return row_type(*row)


def get_multiple_service_db_row(table_name):
    """Return all rows from the given table name.

    Args:
        table_name (str): Table name to search into.

    Yields:
        Iterator[ServiceInspectorRow]: All the rows in the table.
    """
    row_type = _get_service_row_type(table_name)

    query = SELECT_QUERY_TEMPLATE.format(table_name=table_name)
    rows = get_sqlite_query_result(AWS_SERVICES_DB_PATH, query)

    for row in rows:
        yield row_type(*row)
