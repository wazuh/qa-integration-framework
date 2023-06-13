
from wazuh_testing.constants.paths import CVE_DB_PATH
from wazuh_testing.utils.db_interface.basic_queries import make_sqlite_query, get_sqlite_query_result


def get_tables():
    """Get all the table names from the CVE database.

    Returns:
        list(str): Table names.
    """
    return get_sqlite_query_result(CVE_DB_PATH, "SELECT name FROM sqlite_master WHERE type='table';")


def clean_all_cve_tables():
    """Clean all tables from CVE database."""
    query = [f"DELETE FROM {table}" for table in get_tables()]

    # Send all queries in the same batch (instead of calling clean_table method) to avoid so many restarts of wazuh-db
    make_sqlite_query(CVE_DB_PATH, query)