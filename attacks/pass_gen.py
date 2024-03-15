"""
Author: Erez Drutin
Date: 15.03.2024
Purpose: Define a function that generates passwords which are combinations
of commonly used passwords and variations.
"""
from typing import List, Generator


def generate_passwords(base_passwords: List[str], variations: List[str]) -> \
        Generator[str, None, None]:
    """
    Generates passwords by combining base passwords with variations.
    @param base_passwords: The initial format of the commonly used passwords.
    @param variations: The variations to be added to the base passwords.
    @return: A generator that yields the generated passwords.
    """
    for base in base_passwords:
        for variation in variations:
            yield base + variation
