# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
from wazuh_testing.constants.paths.databases import CVE_DB_PATH
from wazuh_testing.utils.database import make_sqlite_query, get_sqlite_query_result


def get_tables() -> list:
    """Get all the table names from the CVE database.

    Returns:
        list(str): Table names.
    """
    return get_sqlite_query_result(CVE_DB_PATH, "SELECT name FROM sqlite_master WHERE type='table';")


def get_rows_from_table(value, column, table, limit=None) -> list:
    """
    Args:
        value (str): value that user wants to find in query
        column (str): Name of the column where the value will be searched for.
        table (str): Name of the table where the value will be searched for.
        limit (int) - Optional: Maximum amount of results to look for. Default None (No Limit used).

    Returns:
        List (str): List with each instance of the value found
    """

    query_string = f"SELECT * FROM {table} WHERE {column} LIKE '{value}'"

    if limit is not None:
        query_string = query_string + f"LIMIT {limit}"

    result = get_sqlite_query_result(CVE_DB_PATH, query_string)
    if len(result) == 0:
        return None

    return result[0]


def get_rows_number(cve_table) -> int:
    """Get the rows number of a specific table from the CVE database

    Args:
        cve_table (str): CVE table name.

    Returns
        int: Number of rows.
    """
    query_string = f"SELECT count(*) from {cve_table}"
    query_result = get_sqlite_query_result(CVE_DB_PATH, query_string)
    rows_number = int(query_result[0])

    return rows_number


def check_inserted_value_exists(table: str, column: str, value: str) -> bool:
    """Check if a value exists in a specific table column.

    Args:
        table (str): Table of cve.db.
        column (str): Column of the table.
        value (str): Value to be checked.

    Returns:
        boolean: True if the specified value exists, False otherwise.
    """
    custom_value = f"'{value}'" if type(value) == str else value
    query_string = f"SELECT count(*) FROM {table} WHERE {column}={custom_value}"
    result = get_sqlite_query_result(CVE_DB_PATH, query_string)
    rows_number = int(result[0])

    return rows_number > 0


def clean_all_cve_tables() -> None:
    """Clean all tables from CVE database."""
    query = [f"DELETE FROM {table}" for table in get_tables()]

    # Send all queries in the same batch (instead of calling clean_table method) to avoid so many restarts of wazuh-manager-db
    make_sqlite_query(CVE_DB_PATH, query)


def clean_nvd_tables() -> None:
    """Clean the NVD tables data"""
    query = [f"DELETE FROM {table}" for table in ['NVD_CVE']]

    # Send all queries in the same batch (instead of calling clean_table method) to avoid so many restarts of wazuh-manager-db
    make_sqlite_query(CVE_DB_PATH, query)


def get_nvd_metadata_timestamp(year) -> str:
    """Get the NVD timestamp data for a specific year from nvd_metadata table.

    Args:
        year (int): NVD feed year. (example: 2022)

    Returns:
        str: Timestamp data. (example: 2022-03-03T03:00:01-05:00)
    """
    query_string = f"SELECT timestamp FROM nvd_metadata WHERE year={year}"
    result = get_sqlite_query_result(CVE_DB_PATH, query_string)

    if len(result) == 0:
        return None

    return result[0]


def update_nvd_metadata_vuldet(timestamp: int) -> None:
    """Update the timestamp value of the nvd_metadata table.

    Args:
        timestamp (int): The new timestamp value to set.
    """
    query_string = f"UPDATE NVD_METADATA SET LAST_UPDATE={timestamp};"
    make_sqlite_query(CVE_DB_PATH, [query_string])


def get_metadata_timestamp(provider_os) -> str:
    """Get the timestamp data for a specific provider_os from metadata table.

    Args:
        provider_os (str): Provider OS. (example: TRUSTY)

    Returns:
        str: Timestamp data. (example: 2022-03-03T03:00:01-05:00)
    """
    query_string = f"SELECT timestamp FROM metadata WHERE target='{provider_os}'"
    result = get_sqlite_query_result(CVE_DB_PATH, query_string)

    if len(result) == 0:
        return None

    return result[0]
