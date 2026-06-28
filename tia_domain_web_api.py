import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from dataclasses import dataclass
from typing import Optional, Dict, Any
from datetime import datetime


class APIError(Exception):
    """Raised for API-level problems (unexpected responses)."""


@dataclass
class DomainInfo:
    domain: str
    data: Dict[str, Any]
    date_first_observed: Optional[datetime] = None

    @staticmethod
    def from_response(domain: str, data: Dict[str, Any]) -> "DomainInfo":
        date_val = None
        df = data.get("date_first_observed")
        if df:
            try:
                date_val = datetime.fromisoformat(df)
            except Exception:
                # keep None if parsing fails
                date_val = None
        return DomainInfo(domain=domain, data=data, date_first_observed=date_val)


class ThreatIntelligenceAggregatorClient:
    """
    Simple client for https://api.threatintelligenceaggregator.org/domain/{domain}
    """

    DEFAULT_BASE = "https://api.threatintelligenceaggregator.org/domain/"

    def __init__(
        self,
        base_url: str = DEFAULT_BASE,
        timeout: float = 10.0,
        max_retries: int = 3,
        backoff_factor: float = 0.3,
    ) -> None:
        self.base_url = base_url
        self.timeout = timeout
        self.session = requests.Session()
        retries = Retry(
            total=max_retries,
            backoff_factor=backoff_factor,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset(["GET"])#, "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]),
        )
        adapter = HTTPAdapter(max_retries=retries)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def _build_url(self, domain: str) -> str:
        domain = domain.strip()
        if not domain:
            raise ValueError("domain must be a non-empty string")
        # ensure no duplicate slashes
        return f"{self.base_url.rstrip('/')}/{domain.lstrip('/')}"

    def get_domain_info(self, domain: str) -> DomainInfo:
        """
        Fetches and returns parsed DomainInfo for the given domain.

        Raises:
            requests.HTTPError: for transport-level HTTP errors
            APIError: for unexpected API payloads
        """
        url = self._build_url(domain)
        resp = self.session.get(url, timeout=self.timeout)
        resp.raise_for_status()
        payload = resp.json()

        # API returns an object keyed by domain name: { "discord.gg": { ... } }
        if isinstance(payload, dict):
            # prefer exact key match
            if domain in payload:
                data = payload[domain]
            elif len(payload) == 1:
                # fallback if caller passed domain slightly differently
                data = next(iter(payload.values()))
            else:
                raise APIError(f"Unexpected payload shape: {payload}")
        else:
            raise APIError(f"Unexpected payload type: {type(payload)}")

        if not isinstance(data, dict):
            raise APIError("Domain data is not an object")

        return DomainInfo.from_response(domain, data)

    def get_raw(self, domain: str) -> Dict[str, Any]:
        """
        Returns the raw JSON payload from the API.
        """
        url = self._build_url(domain)
        resp = self.session.get(url, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()
