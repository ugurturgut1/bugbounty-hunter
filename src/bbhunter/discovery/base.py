from __future__ import annotations

from abc import ABC, abstractmethod

from bbhunter.models import Program


class PlatformConnector(ABC):
    """One connector per platform. Implementations should prefer each
    platform's official API over scraping the app's HTML/JS, since the
    directory pages are client-rendered SPAs and unofficial endpoints
    break without notice.
    """

    platform_name: str

    @abstractmethod
    def is_configured(self) -> bool:
        """Whether credentials/config needed for this connector are present."""

    @abstractmethod
    def fetch_programs(self, *, limit: int | None = None) -> list[Program]:
        """Fetch public programs with normalized scope + policy text.
        Must not perform any testing traffic against listed assets."""
