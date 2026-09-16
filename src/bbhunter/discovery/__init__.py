from bbhunter.discovery.base import PlatformConnector
from bbhunter.discovery.hackerone import HackerOneConnector
from bbhunter.discovery.bugcrowd import BugcrowdConnector
from bbhunter.discovery.intigriti import IntigritiConnector
from bbhunter.discovery.yeswehack import YesWeHackConnector

ALL_CONNECTORS: list[type[PlatformConnector]] = [
    HackerOneConnector,
    BugcrowdConnector,
    IntigritiConnector,
    YesWeHackConnector,
]

__all__ = [
    "PlatformConnector",
    "HackerOneConnector",
    "BugcrowdConnector",
    "IntigritiConnector",
    "YesWeHackConnector",
    "ALL_CONNECTORS",
]
