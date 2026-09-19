import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from dataclasses import dataclass
from typing import Optional, Dict, Any
from datetime import datetime
from urllib.parse import quote


class APIError(Exception):
    """Raised for API-level problems (unexpected responses)."""


class DomainNotFound(APIError):
    """Raised by get_domain_info() when the API has no record of the domain."""


@dataclass
class DomainInfo:
    domain: str
    data: Dict[str, Any]
    date_first_observed: Optional[datetime] = None
    # The date exactly as the API sent it. Kept because parsing can fail or lose
    # information (timezone, precision); callers can re-parse or display it as-is.
    raw_date: Optional[str] = None

    @staticmethod
    def from_response(domain: str, data: Dict[str, Any]) -> "DomainInfo":
        df = data.get("date_first_observed")
        date_val = None
        if df:
            try:
                date_val = datetime.fromisoformat(df)
            except (TypeError, ValueError):
                # keep None if parsing fails; raw_date still holds the original
                date_val = None
        return DomainInfo(
            domain=domain,
            data=data,
            date_first_observed=date_val,
            raw_date=df if isinstance(df, str) and df else None,
        )


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
            allowed_methods=frozenset(["GET"]),
        )
        adapter = HTTPAdapter(max_retries=retries)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def _build_url(self, domain: str) -> str:
        domain = domain.strip().lower()
        if not domain:
            raise ValueError("domain must be a non-empty string")
        # Percent-encode everything, including '/', '?' and '#', so odd input
        # cannot change which endpoint is requested. Leading slashes are dropped
        # first to avoid a duplicate slash after the base URL.
        safe_domain = quote(domain.lstrip("/"), safe="")
        return f"{self.base_url.rstrip('/')}/{safe_domain}"

    def get_raw(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Returns the raw JSON payload from the API, or None if the API has no
        record of the domain (HTTP 404).

        Raises:
            requests.HTTPError: for other HTTP error statuses
            requests.RetryError: when retries on 429/5xx are exhausted
        """
        url = self._build_url(domain)
        resp = self.session.get(url, timeout=self.timeout)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()

    @staticmethod
    def _find_domain_data(domain: str, payload: Dict[str, Any]) -> Optional[Any]:
        """Pick this domain's entry out of the payload; None if it is absent."""
        if not payload:
            return None
        # 1. exact key match (callers pass a lower-cased domain)
        if domain in payload:
            return payload[domain]
        # 2. single-key fallback if the API normalised the name differently
        if len(payload) == 1:
            return next(iter(payload.values()))
        raise APIError(f"Unexpected payload shape: {payload}")

    def get_domain_info(self, domain: str) -> DomainInfo:
        """
        Fetches and returns parsed DomainInfo for the given domain.

        Raises:
            DomainNotFound: the API has no record of the domain (HTTP 404, or an
                empty payload). Subclass of APIError.
            APIError: for unexpected API payloads
            requests.HTTPError: for other HTTP error statuses
            requests.RetryError: when retries on 429/5xx are exhausted
        """
        # DNS names are case-insensitive; look up and match on the lower-cased name.
        domain = domain.strip().lower()
        payload = self.get_raw(domain)
        if payload is None:
            raise DomainNotFound(f"No record for domain: {domain}")

        # API returns an object keyed by domain name: { "discord.gg": { ... } }
        if not isinstance(payload, dict):
            raise APIError(f"Unexpected payload type: {type(payload)}")

        data = self._find_domain_data(domain, payload)
        if data is None:
            raise DomainNotFound(f"No record for domain: {domain}")
        if not isinstance(data, dict):
            raise APIError("Domain data is not an object")

        return DomainInfo.from_response(domain, data)
