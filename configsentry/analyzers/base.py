from abc import ABC, abstractmethod
import httpx
from configsentry.core.models import SecurityIssue, RiskLevel

class BaseAnalyzer(ABC):
    """
    Abstract base class for all security configuration analyzers.
    Follows Strategy Pattern for extensible scanner design.
    """
    
    @abstractmethod
    async def analyze(self, response: httpx.Response) -> list[SecurityIssue]:
        """
        Executes analysis on HTTP response and returns identified issues.
        """
        pass