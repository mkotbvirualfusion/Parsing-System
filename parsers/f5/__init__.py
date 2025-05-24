"""
F5 Networks device parsers for the Network Configuration Parser.
"""

from .tmos_parser import F5TMOSParser
from .f5os_parser import F5OSParser

__all__ = [
    'F5TMOSParser',
    'F5OSParser'
] 