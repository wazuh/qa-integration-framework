"""
Copyright (C) 2015-2023, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import os
import json
import socket
import time
from typing import List, Union
import select

from wazuh_testing.constants.daemons import WAZUH_DB_DAEMON
from wazuh_testing.constants.paths.sockets import QUEUE_DB_PATH, WAZUH_DB_SOCKET_PATH
from wazuh_testing.tools.db_administrator import DatabaseAdministrator
from wazuh_testing.utils import services, secure_message


def delete_dbs():
    """Delete all wazuh-manager-db databases."""
    for root, dirs, files in os.walk(QUEUE_DB_PATH):
        for file in files:
            os.remove(os.path.join(root, file))


def query_wdb(command, response_only=True, multiple_responses=False) -> List[str]:
    """Make queries to wazuh-manager-db using the wdb socket.

    Args:
        command (str): wazuh-manager-db command alias. For example `global get-agent-info 000`.

    Returns:
        list: Query response data.
    """
    # If the wdb socket is not yet up, then wait or restart wazuh-manager-db
    if not os.path.exists(WAZUH_DB_SOCKET_PATH):
        max_retries = 6
        for _ in range(2):
            retry = 0
            # Wait if the wdb socket is not still alive (due to wazuh-manager-db restarts). Max 3 seconds
            while not os.path.exists(WAZUH_DB_SOCKET_PATH) and retry < max_retries:
                time.sleep(0.5)
                retry += 1

            # Restart wazuh-manager-db in case of wdb socket is not yet up.
            if not os.path.exists(WAZUH_DB_SOCKET_PATH):
                services.control_service('restart', daemon=WAZUH_DB_DAEMON)

        # Raise custom exception if the socket is not up in the expected time, even restarting wazuh-manager-db
        if not os.path.exists(WAZUH_DB_SOCKET_PATH):
            raise Exception('The wdb socket is not up. wazuh-manager-db was restarted but the socket was not found')

    # Create and open the socket connection with wazuh-manager-db socket
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(WAZUH_DB_SOCKET_PATH)
    data = []

    try:
        # Send the query request
        sock.send(secure_message.pack(len(command)) + command.encode())

        rcv = sock.recv(4)
        data_array = []
        if len(rcv) == 4:
            data_len = secure_message.unpack(rcv)

            data = sock.recv(data_len).decode()

            if(multiple_responses):
                while(data != ''):
                    data_array.append(data)
                    data = ''
                    # Wait until there is data to receive
                    ready = select.select([sock], [], [], 5)
                    if ready[0]:
                        rcv = sock.recv(4)
                        data_len = secure_message.unpack(rcv)
                        data = sock.recv(data_len).decode()

            # Remove response header and cast str to list of dictionaries
            # From --> 'ok [ {data1}, {data2}...]' To--> [ {data1}, data2}...]
            if len(data.split()) > 1 and data.split()[0] == 'ok':
                if response_only:
                    try:
                        data = json.loads(' '.join(data.split(' ')[1:]))
                    except ValueError as e:
                        data = ' '.join(data.split(' ')[1:])

    finally:
        sock.close()

    if(multiple_responses):
        return data_array[0] if len(data_array) == 1 else data_array

    return data


def make_sqlite_query(db_path: str, query_list: List[str]) -> None:
    """Make a query to the database for each passed query.
    Args:
        db_path (string): Path where is located the DB.
        query_list (list): List with queries to run.
    """
    services.control_service('stop', daemon=WAZUH_DB_DAEMON)

    try:
        with DatabaseAdministrator(db_path) as db:
            for query in query_list:
                db.execute_query(query)
    finally:
        services.control_service('start', daemon=WAZUH_DB_DAEMON)


def get_sqlite_query_result(db_path: str, query: str) -> List[str]:
    """Execute a query in a given database and return the result.
    Args:
        db_path (str): Path where is located the DB.
        query (str): SQL query. e.g(SELECT * ..).
    Returns:
        result (List[list]): Each row is the query result row and each column is the query field value.
    """
    services.control_service('stop', daemon=WAZUH_DB_DAEMON)

    try:
        with DatabaseAdministrator(db_path) as db:
            records = db.execute_query(query)
            result = []

            for row in records:
                result.append(', '.join([f"{item}" for item in row]))

            return result
    finally:
        services.control_service('start', daemon=WAZUH_DB_DAEMON)


def get_sqlite_fetch_one_query_result(db_path: str, query: str) -> tuple:
    """Execute a query expecting only one result in a given database and return the result.
    Args:
        db_path (str): Path where is located the DB.
        query (str): SQL query. e.g(SELECT * ..).
    Returns:
        result (tuple): Query result row.
    """
    services.control_service('stop', daemon=WAZUH_DB_DAEMON)

    try:
        with DatabaseAdministrator(db_path) as db:
            records = db.execute_fetch_one_query(query)
            
            return records
    finally:
        services.control_service('start', daemon=WAZUH_DB_DAEMON)


def run_sql_script(database_path: Union[os.PathLike, str], script_path: Union[os.PathLike, str]) -> None:
    """Run SQL script in a database.
    Args:
        database_path (os.PathLike or str): Path to the SQLite database.
        script_path (os.PathLike or str): SQL script to be executed.
    """
    with DatabaseAdministrator(database_path) as db:
        db.execute_script(script_path)
