"""
Author: Erez Drutin
Date: 04.11.2023
Purpose: Provide DB handling functionality for the rest of the messages_server code.
This file contains the DatabaseHandler definition, which consists of all DB
interactions between the Server and our sqlite database.
"""

import sqlite3
from datetime import datetime
from typing import List, Union, Type, Dict, Any, Optional
import common.models as models
import logging


class DatabaseHandler:
    def __init__(self, db_file: str, config: Dict[str, Any],
                 logger: logging.Logger, client_tbl: Optional[str] = '',
                 servers_tbl: Optional[str] = ''):
        """
        @param db_file: A path to the file in which the DB is stored.
        @param config: A dict that is expected to be formatted as follows:
        {
            "tbl": {
                "fetch_init": "Query to extract initial results from",
                "data_class": "Matching dataclass name to table values"
            }
        }
        @param logger: A logger to use to log messages.
        @param client_tbl: An optional table of clients.
        @param servers_tbl: An optional table of messages servers.
        """
        self.db_file = db_file
        self.config = config
        self.client_tbl = client_tbl
        self.servers_tbl = servers_tbl
        self.logger = logger

    def _connect(self):
        # Set a busy timeout of 20 seconds
        conn = sqlite3.connect(self.db_file, timeout=20)
        # Enable WAL mode (Write ahead logging for read & writes to proceed
        # concurrently by writing changes to a log file first:
        conn.execute('PRAGMA journal_mode=WAL;')
        return conn

    def table_exists(self, table_name: str) -> bool:
        query = f"SELECT count(name) FROM sqlite_master WHERE type='table' " \
                f"AND name='{table_name}'"
        # The query returns a list of tuples, where the value is expected to
        # be 1 if the table exists, 0 if not:
        try:
            return self.perform_query(query)[0][0] == 1
        except sqlite3.Error as err:
            self.logger.error(f"Failed to check if '{table_name}' exists in "
                              f"the DB or not. Exception: {err}")
            raise err

    def perform_query(self, query: str, *args, **kwargs) -> List[Any]:
        """
        Receives a query string and attempts to perform it. Returns the
        result of the execution of the query.
        @param query: A query to perform.
        @param args: Optional additional args.
        @param kwargs: Optional additional kwargs.
        @return: A list of rows, where row resembles a query result record.
        """
        try:
            with self._connect() as conn:
                cur = conn.cursor()
                cur.execute(query, args or kwargs)
                return [row for row in cur.fetchall()]
        except (sqlite3.Error, Exception) as err:
            self.logger.warning(f"An exception was raised while performing "
                                f"the query: {query}. Exception: {err}")
            raise err

    def perform_query_to_data_model(
            self, query: str, data_class: Type[models.T], *args,
            **kwargs) -> List[Any]:
        """
        Receives a query and a dataclass to convert the query results to.
        Returns the result of the execution of the query as dataclass
        instantiated instances. We are not catching sqlite3 errors here by
        intent, so the relevant methods can handle this case.
        @param query: A query to perform.
        @param data_class: A dataclass to convert the query results to.
        @param args: Optional additional args.
        @param kwargs: Optional additional kwargs.
        @return: A list of dataclasses, where each dataclass resembles a query
        result record.
        """
        try:
            return [data_class(*row) for row in
                    self.perform_query(query, *args, **kwargs)]
        except TypeError as err:
            self.logger.error(f"Failed to convert the results of the query "
                              f"'{query}' into the dataclass: "
                              f"'{data_class.__name__}'. Exception: {err}")

    def cache_tables_data(self) -> Dict:
        """
        Expects a config dict and returns a mapping of table-datamodels lists.
        @return: A dictionary populated with tables and a list of datamodels
        that represent their values in the DB.
        """
        results = {}
        try:
            for table_name, table_info in self.config.items():
                # Fetching cached results from the tables if they exist:
                if self.table_exists(table_name):
                    results[table_name] = self.perform_query_to_data_model(
                        table_info.get("fetch_init"),
                        getattr(models, table_info.get("data_class")))
                # Creating tables & adding them, perform_query will return []:
                else:
                    results[table_name] = self.perform_query(table_info.get(
                        "create_command"))
            return results
        except sqlite3.Error:
            # Assuming no cached data from the DB in case of failure:
            return {table_name: [] for table_name in self.config.keys()}

    def update_client_last_seen(self, client_id: bytes) -> None:
        """
        Updates the last seen value in the DB for the received client_side id.
        Letting the code "crash" in case of failure.
        @param client_id: The id of the client_side to update.
        """
        self.perform_query(query=self.config[self.client_tbl].get(
            'update_client_last_seen'), id=client_id, last_seen=datetime.now())

    def get_client_by_name(self, name: str) -> Union[models.Client, None]:
        """
        Receives a client_side name and attempts to fetch it from the DB.
        Returns either a client_side instance or None if failed to find one.
        Letting the code "crash" in case of failure.
        @param name: The name of the client_side to fetch.
        @return: A client_side instantiated dataclass instance.
        """
        results = self.perform_query_to_data_model(
            query=self.config[self.client_tbl].get('get_client_by_name'),
            data_class=models.Client, name=name)
        return None if not len(results) else results[0]

    def get_client_by_id(self, _id: bytes) -> Union[models.Client, None]:
        """
        Receives a client id and attempts to fetch it from the DB.
        Returns either a client_side instance or None if failed to find one.
        Letting the code "crash" in case of failure.
        @param _id: The id of the client_side to fetch.
        @return: A client_side instantiated dataclass instance.
        """
        results = self.perform_query_to_data_model(
            query=self.config[self.client_tbl].get('get_client_by_id'),
            data_class=models.Client, id=_id)
        return None if not len(results) else results[0]

    def add_client(self, client: models.Client) -> bool:
        """
        Receives a client_side dataclass and attempts to add it to the DB.
        Letting the code "crash" in case of failure.
        @param client: The properties of the client_side to add.
        @return: A boolean indicating whether the operation succeeded or not.
        """
        try:
            self.perform_query(query=self.config[self.client_tbl].get(
                'add_client'), id=client.id, name=client.name,
                password_hash=client.password_hash, last_seen=client.last_seen)
            return True
        except (sqlite3.Error, Exception):
            self.logger.error(f"Failed to add client '{client.name}' to DB.")
            return False

    def add_server(self, server: models.Server) -> bool:
        """
        Receives a file dataclass and attempts to add it to the DB.
        Letting the code "crash" in case of failure.
        @param server: The properties of the server to add.
        @return: A boolean indicating whether the operation succeeded or not.
        """
        try:
            self.perform_query(query=self.config[self.servers_tbl].get(
                'add_server'), id=server.id, name=server.name, ip=server.ip,
                port=server.port, aes_key=server.aes_key,
                version=server.version)
            return True
        except sqlite3.IntegrityError:
            self.logger.info(f"Skipping insertion, server with ID "
                             f"'{server.id}' and name '{server.name}' "
                             f"already exists.")
            return False

    def get_servers(self) -> Union[List[models.Server], None]:
        """
        Attempts to fetch all servers from the DB. Returns None in case of
        failure to fetch any results.
        @return: All registered servers from the DB as instantiated dataclass
        instances.
        """
        try:
            results = self.perform_query_to_data_model(
                query=self.config[self.servers_tbl].get('get_servers'),
                data_class=models.Server)
            return results
        except sqlite3.IntegrityError:
            self.logger.info("Failed to fetch any message servers from the DB")
            return None

    def get_server_by_id(self, server_id: bytes) -> Union[models.Server, None]:
        """
        Receives a server id and attempts to fetch it from the DB.
        Returns either a client_side instance or None if failed to find one.
        Letting the code "crash" in case of failure.
        @param server_id: The id of the server to fetch.
        @return: A server instantiated dataclass instance.
        """
        results = self.perform_query_to_data_model(
            query=self.config[self.servers_tbl].get('get_server_by_id'),
            data_class=models.Server, id=server_id)
        return None if not len(results) else results[0]
    # def get_aes_key_for_server(self, server_id: bytes) -> bytes:
    #     """
    #     Receives a client_id and returns its matching AES key. Letting the
    #     code "crash" in case of failure.
    #     @param server_id: A client_side id to fetch an AES key for.
    #     @return: A bytes sequence representing the requested AES key.
    #     """
    #     # Selecting the first record from the first row in the results:
    #     return self.perform_query(query=self.config[self.servers_tbl].get(
    #         'get_server_aes'), id=server_id)[0][0]

    # def update_public_key_and_aes_key(self, client_id: bytes, aes_key: bytes,
    #                                   public_key: bytes) -> None:
    #     """
    #     Receives a client_id, public key and an aes_key. Updates the public
    #     key and the aes key for the received client_id (+ last seen time).
    #     @param client_id: A client_side id to update values for.
    #     @param aes_key: An aes key to update.
    #     @param public_key: A public key to update.
    #     """
    #     self.perform_query(query=self.config[self.client_tbl].get(
    #         'update_public_aes'), id=client_id, public_key=public_key,
    #         aes_key=aes_key, last_seen=datetime.now())
