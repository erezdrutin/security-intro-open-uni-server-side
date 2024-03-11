"""
Author: Erez Drutin
Date: 04.11.2023
Purpose: Provide File handling functionality for the rest of the messages_server code.
This file contains the FileHandler definition, which consists of all of our
interactions with the FileSystem via the Server.
"""
import logging
import os
from typing import Any, Union


class FileHandler:
    def __init__(self, filepath, logger: logging.Logger):
        self.filepath = filepath
        self.logger = logger

    def _validate_dir(self):
        """
        Ensures that the dir path in which the file is expected to exist is
        valid. If not, attempts to create it. This will attempt to
        "recursively build the paths", in the sense that if we pass
        "X/files/file.txt", and any of the path parts is not defined (or all of
        them), then this method will create the necessary directories for
        it, meaning that both "X" and "X/files" will be created.
        """
        directory = os.path.dirname(self.filepath)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)

    def load_value(self, default_value=None, mode='r') -> Union[str, None]:
        """
        Load a single value (e.g., port) from the specified file.
        Returns a default value if the file is not found.
        """
        try:
            with open(self.filepath, mode) as file:
                value = file.read().strip()
            return value
        except (FileNotFoundError, OSError):
            self.logger.error(f"Error: {self.filepath} not found.")
            if default_value:
                self.logger.info(f"Running on port {default_value} instead...")
                return default_value
            return None

    def write_value(self, value: Any) -> bool:
        """
        Writes the received value to self.filepath. If the received value is
        of type bytes, we will use "wb" to write binary. Otherwise, we will
        use "w" with "utf-8" encoding.
        @param value: A value to write to self.filepath.
        @return: True if succeeded, False if not.
        """
        """
        Write a single value (e.g., port) to the specified file.
        """
        try:
            self._validate_dir()
            if isinstance(value, bytes):
                with open(self.filepath, 'wb') as file:
                    file.write(value)
            else:
                with open(self.filepath, 'w', encoding='utf-8') as file:
                    file.write(str(value))
            return True
        except OSError as e:
            self.logger.error(f"Error writing to {self.filepath}: {e}")
            return False
