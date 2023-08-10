"""
Copyright (C) 2015-2023, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import os
import itertools
import sqlite3
from typing import Tuple, Union

from wazuh_testing.logger import logger


class DatabaseAdministrator:
    def __init__(self, db_path: Union[os.PathLike, str]):
        self.db_path = db_path
        self.connection = sqlite3.connect(self.db_path)
        self.cursor = self.connection.cursor()
        logger.info(f"Connection established with {self.db_path}")


    def create_table(self, table_name: str, columns: str) -> None:
        query = f"CREATE TABLE IF NOT EXISTS {table_name} ({columns})"
        self.cursor.execute(query)
        logger.info(f"Table '{table_name}' created")


    def execute_script(self, sql_script: Union[os.PathLike, str]) -> None:
        with open(sql_script) as file:
            sql = file.read()
            self.cursor.executescript(sql)


    def execute_query(self, query: str) -> list:
        self.cursor.execute(query)
        rows = self.cursor.fetchall()
        
        return rows


    def insert(self, table_name: str, values: Tuple) -> None:
        placeholders = ', '.join(itertools.repeat('?', len(values)))
        query = f"INSERT INTO {table_name} VALUES ({placeholders})"
        self.cursor.execute(query, values)
        logger.info('Data inserted')


    def select(self, table_name: str, condition: str = '') -> list:
        query = f"SELECT * FROM {table_name}"
        if condition:
            query += f" WHERE {condition}"
        self.cursor.execute(query)
        rows = self.cursor.fetchall()

        return rows


    def delete(self, table_name: str, condition: str = '') -> None:
        query = f"DELETE FROM {table_name}"
        if condition:
            query += f" WHERE {condition}"
        self.cursor.execute(query)
        logger.info('Data deleted')


    # Context Manager
    def __enter__(self):
        return self


    def __exit__(self, ext_type, exc_value, traceback):
        self.cursor.close()
        if isinstance(exc_value, Exception):
            self.connection.rollback()
        else:
            self.connection.commit()
        self.connection.close()
