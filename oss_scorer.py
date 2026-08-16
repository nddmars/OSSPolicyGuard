import json
import os
import time
import logging
import warnings
import yaml
import pandas as pd
import requests
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
import matplotlib.pyplot as plt
from ipywidgets import interact, Dropdown
import ipywidgets as widgets
from IPython.display import display, Markdown

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(name)s %(levelname)s %(message)s'
)
logger = logging.getLogger(__name__)


class ProviderStatus(str, Enum):
    SUCCESS = "success"
    TIMEOUT = "timeout"
    RATE_LIMIT = "rate_limit"
    MALFORMED = "malformed"
    NETWORK_ERROR = "network_error"
    UNKNOWN = "unknown"


@dataclass
class ProviderError:
    provider: str
    status: ProviderStatus
    message: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "status": self.status.value,
            "message": self.message,
            "details": self.details,
        }


@dataclass
class ProviderResponse:
    provider: str
    status: ProviderStatus
    fetched_at: str
    data: dict[str, Any] = field(default_factory=dict)
    error: ProviderError | None = None

    def is_success(self) -> bool:
        return self.status == ProviderStatus.SUCCESS


class SimpleCache:
    def __init__(self) -> None:
        self._store: dict[str, tuple[ProviderResponse, float]] = {}

    def get(self, key: str) -> ProviderResponse | None:
        entry = self._store.get(key)
        if not entry:
            return None
        response, expires_at = entry
        if time.monotonic() < expires_at:
            return response
        self._store.pop(key, None)
        return None

    def set(self, key: str, response: ProviderResponse, ttl: float) -> None:
        self._store[key] = (response, time.monotonic() + ttl)


class ProviderBase:
    def __init__(
        self,
        config: dict[str, Any],
        provider: str,
        timeout_key: str | None = None,
        token_key: str | None = None,
        rate_limit: float = 1.0,
        cache_ttl: float = 60.0,
    ) -> None:
        self.config = config
        self.name = provider
        self.timeout_key = timeout_key
        self.token_key = token_key
        self.rate_limit = rate_limit
        self.cache_ttl = cache_ttl
        self.cache = SimpleCache()
        self._last_request_time = 0.0

    @property
    def timeout(self) -> int:
        if self.timeout_key:
            return int(self.config.get(self.timeout_key, {}).get("timeout", 10))
        return 10

    def _build_headers(self, service: str | None = None) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self.token_key and self.config.get(self.token_key, {}).get("token"):
            headers["Authorization"] = f'token {self.config[self.token_key]["token"]}'
        if service == "scorecard":
            headers["Accept"] = "application/json"
        return headers

    def _build_cache_key(self, url: str, params: dict[str, Any] | None) -> str:
        return f"{url}?{json.dumps(params or {}, sort_keys=True, default=str)}"

    def _sleep_rate_limit(self) -> None:
        min_interval = 1.0 / max(1.0, self.rate_limit)
        elapsed = time.monotonic() - self._last_request_time
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        self._last_request_time = time.monotonic()

    def _get(
        self,
        url: str,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        timeout: int | None = None,
        retries: int = 2,
        backoff_factor: float = 0.5,
    ) -> ProviderResponse:
        cache_key = self._build_cache_key(url, params)
        cached = self.cache.get(cache_key)
        if cached:
            return cached

        headers = headers or {}
        timeout = timeout or self.timeout
        attempt = 0
        while attempt <= retries:
            self._sleep_rate_limit()
            try:
                response = requests.get(url, params=params, headers=headers, timeout=timeout)
                response.raise_for_status()
                try:
                    payload = response.json()
                except ValueError as exc:
                    error = ProviderError(
                        self.name,
                        ProviderStatus.MALFORMED,
                        f"Invalid JSON response from {url}",
                        {"exception": str(exc)},
                    )
                    return ProviderResponse(
                        self.name,
                        ProviderStatus.MALFORMED,
                        datetime.now(timezone.utc).isoformat(),
                        error=error,
                    )

                result = ProviderResponse(
                    self.name,
                    ProviderStatus.SUCCESS,
                    datetime.now(timezone.utc).isoformat(),
                    data=payload,
                )
                self.cache.set(cache_key, result, self.cache_ttl)
                return result
            except requests.HTTPError as exc:
                status = ProviderStatus.RATE_LIMIT if exc.response is not None and exc.response.status_code == 429 else ProviderStatus.NETWORK_ERROR
                message = f"HTTP error {exc.response.status_code if exc.response else 'unknown'} for {url}"
            except requests.Timeout as exc:
                status = ProviderStatus.TIMEOUT
                message = f"Request timeout for {url}: {exc}"
            except requests.RequestException as exc:
                status = ProviderStatus.NETWORK_ERROR
                message = f"Network error for {url}: {exc}"
            except Exception as exc:  # pragma: no cover
                status = ProviderStatus.UNKNOWN
                message = f"Unexpected error for {url}: {exc}"
            attempt += 1
            if attempt > retries:
                error = ProviderError(self.name, status, message, {"attempts": attempt})
                return ProviderResponse(
                    self.name,
                    status,
                    datetime.now(timezone.utc).isoformat(),
                    error=error,
                )
            time.sleep(backoff_factor * (2 ** (attempt - 1)))

    def fetch(self, *args: Any, **kwargs: Any) -> ProviderResponse:
        raise NotImplementedError("Providers must implement fetch()")


class GitHubProvider(ProviderBase):
    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config, "github", timeout_key="github", token_key="github", rate_limit=float(config.get("github", {}).get("rate_limit", 1)), cache_ttl=60.0)

    def _parse_github_owner_repo(self, url: str) -> tuple[str, str]:
        parsed = urlparse(url.rstrip("/"))
        if parsed.netloc not in ("github.com", "www.github.com"):
            raise ValueError(f"Not a GitHub URL: {url!r}")
        parts = [p for p in parsed.path.split("/") if p]
        if len(parts) < 2:
            raise ValueError(f"Cannot extract owner/repo from URL: {url!r}")
        repo_name = parts[-1]
        if repo_name.endswith('.git'):
            repo_name = repo_name[:-4]
        return parts[-2], repo_name

    def fetch(self, repo_url: str) -> ProviderResponse:
        try:
            owner, repo = self._parse_github_owner_repo(repo_url)
        except ValueError as exc:
            return ProviderResponse(
                self.name,
                ProviderStatus.UNKNOWN,
                datetime.now(timezone.utc).isoformat(),
                error=ProviderError(self.name, ProviderStatus.UNKNOWN, str(exc)),
            )

        response = self._get(
            f"https://api.github.com/repos/{owner}/{repo}",
            headers=self._build_headers("github"),
        )
        if not response.is_success():
            return response

        body = response.data
        normalized = {
            'stars': body.get('stargazers_count', 0),
            'forks': body.get('forks_count', 0),
            'last_commit': body.get('pushed_at', ''),
            'open_issues': body.get('open_issues_count', 0),
            'contributors_url': body.get('contributors_url', ''),
        }
        return ProviderResponse(self.name, ProviderStatus.SUCCESS, response.fetched_at, data=normalized)


class ScorecardProvider(ProviderBase):
    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config, "scorecard", timeout_key="scorecard", rate_limit=1.0, cache_ttl=300.0)

    def _parse_github_owner_repo(self, url: str) -> tuple[str, str]:
        parsed = urlparse(url.rstrip("/"))
        if parsed.netloc not in ("github.com", "www.github.com"):
            raise ValueError(f"Not a GitHub URL: {url!r}")
        parts = [p for p in parsed.path.split("/") if p]
        if len(parts) < 2:
            raise ValueError(f"Cannot extract owner/repo from URL: {url!r}")
        repo_name = parts[-1]
        if repo_name.endswith('.git'):
            repo_name = repo_name[:-4]
        return parts[-2], repo_name

    def fetch(self, repo_url: str) -> ProviderResponse:
        try:
            owner, repo = self._parse_github_owner_repo(repo_url)
        except ValueError as exc:
            return ProviderResponse(
                self.name,
                ProviderStatus.UNKNOWN,
                datetime.now(timezone.utc).isoformat(),
                error=ProviderError(self.name, ProviderStatus.UNKNOWN, str(exc)),
            )

        response = self._get(
            f"https://api.securityscorecards.dev/projects/github.com/{owner}/{repo}",
            headers=self._build_headers("scorecard"),
        )
        if not response.is_success():
            return response

        body = response.data
        normalized = {
            'score': float(body.get('score', 0)),
            'date': body.get('date', ''),
            'checks': {c.get('name', ''): c.get('score', -1) for c in body.get('checks', [])},
        }
        return ProviderResponse(self.name, ProviderStatus.SUCCESS, response.fetched_at, data=normalized)


# Scoring constants
_STARS_HIGH_THRESHOLD = 10_000
_STARS_MED_THRESHOLD = 1_000
_STARS_LOW_THRESHOLD = 100
_FORKS_HIGH_THRESHOLD = 5_000
_FORKS_MED_THRESHOLD = 1_000
_FORKS_LOW_THRESHOLD = 100

# EPSS exploit-probability deduction thresholds (points deducted per CVE)
_EPSS_HIGH_THRESHOLD = 0.5     # ≥ 0.5 → actively weaponised
_EPSS_MED_THRESHOLD = 0.1      # 0.1–0.5 → meaningful exploitation risk
_DEDUCT_EPSS_HIGH = 15         # confirmed active exploit
_DEDUCT_EPSS_MED = 8           # moderate exploitation risk
_DEDUCT_EPSS_LOW = 2           # theoretical / low probability
_DEDUCT_CVSS_CRITICAL = 10     # CRITICAL severity, no EPSS data
_DEDUCT_CVSS_HIGH = 5          # HIGH severity, no EPSS data
_DEDUCT_CVSS_MEDIUM = 2        # MEDIUM severity, no EPSS data

# NVD CVE look-back window (days)
_CVE_LOOKBACK_DAYS = 3 * 365

_VALID_CRITICALITY = {"Mission Critical", "Business Critical", "Non-Critical"}

# Map OSSPolicyGuard registry names to OSV.dev ecosystem identifiers
_OSV_ECOSYSTEM_MAP: dict[str, str] = {
    'npm':       'npm',
    'pypi':      'PyPI',
    'rubygems':  'RubyGems',
    'crates':    'crates.io',
    'nuget':     'NuGet',
    'packagist': 'Packagist',
    'maven':     'Maven',
}

# Fast-path lookup: lowercase location token → ISO-3166-1 alpha-2 country code.
# Covers the high-risk countries from config plus the most common contributor locations
# so that Nominatim is only needed for rare/ambiguous strings.
_LOCATION_COUNTRY_MAP: dict[str, str] = {
    # ── High-risk nations ──────────────────────────────────────────────────
    'china': 'CN', 'prc': 'CN', 'beijing': 'CN', 'shanghai': 'CN',
    'shenzhen': 'CN', 'guangzhou': 'CN', 'hangzhou': 'CN', 'chengdu': 'CN',
    'wuhan': 'CN', 'nanjing': 'CN', 'xian': 'CN', 'tianjin': 'CN',
    '中国': 'CN', '北京': 'CN', '上海': 'CN', '深圳': 'CN',
    'russia': 'RU', 'russian federation': 'RU', 'moscow': 'RU',
    'saint petersburg': 'RU', 'st. petersburg': 'RU', 'novosibirsk': 'RU',
    'iran': 'IR', 'tehran': 'IR', 'isfahan': 'IR', 'mashhad': 'IR',
    'north korea': 'KP', 'pyongyang': 'KP', 'dprk': 'KP',
    'syria': 'SY', 'damascus': 'SY', 'aleppo': 'SY',
    # ── United States ──────────────────────────────────────────────────────
    'united states': 'US', 'usa': 'US', 'u.s.': 'US', 'u.s.a.': 'US',
    'new york': 'US', 'san francisco': 'US', 'seattle': 'US', 'boston': 'US',
    'chicago': 'US', 'austin': 'US', 'los angeles': 'US', 'portland': 'US',
    'mountain view': 'US', 'san jose': 'US', 'redmond': 'US', 'menlo park': 'US',
    'palo alto': 'US', 'denver': 'US', 'atlanta': 'US', 'raleigh': 'US',
    # ── United Kingdom ─────────────────────────────────────────────────────
    'united kingdom': 'GB', 'uk': 'GB', 'england': 'GB', 'london': 'GB',
    'manchester': 'GB', 'cambridge': 'GB', 'oxford': 'GB', 'edinburgh': 'GB',
    'bristol': 'GB', 'glasgow': 'GB',
    # ── Germany ────────────────────────────────────────────────────────────
    'germany': 'DE', 'deutschland': 'DE', 'berlin': 'DE', 'munich': 'DE',
    'münchen': 'DE', 'hamburg': 'DE', 'frankfurt': 'DE', 'cologne': 'DE',
    # ── France ─────────────────────────────────────────────────────────────
    'france': 'FR', 'paris': 'FR', 'lyon': 'FR', 'toulouse': 'FR',
    # ── Canada ─────────────────────────────────────────────────────────────
    'canada': 'CA', 'toronto': 'CA', 'vancouver': 'CA', 'montreal': 'CA',
    'calgary': 'CA', 'ottawa': 'CA',
    # ── Australia ──────────────────────────────────────────────────────────
    'australia': 'AU', 'sydney': 'AU', 'melbourne': 'AU', 'brisbane': 'AU',
    # ── India ──────────────────────────────────────────────────────────────
    'india': 'IN', 'bangalore': 'IN', 'bengaluru': 'IN', 'mumbai': 'IN',
    'hyderabad': 'IN', 'pune': 'IN', 'delhi': 'IN', 'new delhi': 'IN',
    'chennai': 'IN', 'kolkata': 'IN',
    # ── Netherlands / Nordics ──────────────────────────────────────────────
    'netherlands': 'NL', 'amsterdam': 'NL', 'the netherlands': 'NL',
    'sweden': 'SE', 'stockholm': 'SE', 'gothenburg': 'SE',
    'norway': 'NO', 'oslo': 'NO',
    'denmark': 'DK', 'copenhagen': 'DK',
    'finland': 'FI', 'helsinki': 'FI',
    # ── Other common ───────────────────────────────────────────────────────
    'japan': 'JP', 'tokyo': 'JP', 'osaka': 'JP',
    'south korea': 'KR', 'seoul': 'KR',
    'switzerland': 'CH', 'zurich': 'CH', 'zürich': 'CH', 'bern': 'CH',
    'austria': 'AT', 'vienna': 'AT', 'wien': 'AT',
    'poland': 'PL', 'warsaw': 'PL', 'krakow': 'PL',
    'spain': 'ES', 'madrid': 'ES', 'barcelona': 'ES',
    'italy': 'IT', 'rome': 'IT', 'milan': 'IT',
    'brazil': 'BR', 'são paulo': 'BR', 'sao paulo': 'BR', 'rio de janeiro': 'BR',
    'israel': 'IL', 'tel aviv': 'IL',
    'singapore': 'SG',
    'taiwan': 'TW', 'taipei': 'TW',
    'new zealand': 'NZ', 'auckland': 'NZ',
    'ukraine': 'UA', 'kyiv': 'UA', 'kiev': 'UA',
    'czechia': 'CZ', 'czech republic': 'CZ', 'prague': 'CZ',
    'portugal': 'PT', 'lisbon': 'PT',
    'belgium': 'BE', 'brussels': 'BE',
}


# Configuration Manager
class OSSConfig:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(OSSConfig, cls).__new__(cls)
            cls._instance._load_config()
        return cls._instance

    def _load_config(self):
        """Internal method to load configuration"""
        try:
            config_path = Path('config.yaml')
            if not config_path.exists():
                raise FileNotFoundError("config.yaml not found")

            with open(config_path) as f:
                self.config = yaml.safe_load(f) or {}

            # Set defaults
            self.config.setdefault('nvd', {})
            self.config['nvd'].setdefault('api_key', '')
            self.config['nvd'].setdefault('rate_limit', 5)

            self.config.setdefault('github', {})
            self.config['github'].setdefault('token', '')
            self.config['github'].setdefault('timeout', 10)

            self.config.setdefault('scoring', {})
            self.config['scoring'].setdefault('weights', {})
            self.config['scoring']['weights'].setdefault('activity', 30)
            self.config['scoring']['weights'].setdefault('trust', 20)
            self.config['scoring']['weights'].setdefault('security', 35)
            self.config['scoring']['weights'].setdefault('community', 15)

            # Community sub-section defaults
            self.config['scoring'].setdefault('community', {})
            comm = self.config['scoring']['community']
            comm.setdefault('weekly_high', 1_000_000)
            comm.setdefault('weekly_med', 100_000)
            comm.setdefault('weekly_low', 10_000)
            comm.setdefault('download_weight', 0.7)
            comm.setdefault('star_weight', 0.3)

            # Registry defaults — only applied when registries section is absent
            self.config.setdefault('registries', {
                'npm':       {'enabled': True, 'timeout': 10,
                              'languages': ['javascript', 'typescript', 'nodejs', 'node']},
                'pypi':      {'enabled': True, 'timeout': 10, 'languages': ['python']},
                'rubygems':  {'enabled': True, 'timeout': 10, 'languages': ['ruby']},
                'crates':    {'enabled': True, 'timeout': 10, 'languages': ['rust']},
                'nuget':     {'enabled': True, 'timeout': 10,
                              'languages': ['csharp', 'c#', 'dotnet']},
                'packagist': {'enabled': True, 'timeout': 10, 'languages': ['php']},
                'maven':     {'enabled': False, 'timeout': 10,
                              'languages': ['java', 'kotlin', 'scala', 'groovy']},
            })

            # OSV and malicious-package check defaults
            self.config.setdefault('osv', {})
            self.config['osv'].setdefault('enabled', True)
            self.config['osv'].setdefault('timeout', 10)
            self.config['osv'].setdefault('extra_advisory_deduction', 3)
            self.config['osv'].setdefault('extra_advisory_max_penalty', 20)

            self.config.setdefault('malicious_packages', {})
            self.config['malicious_packages'].setdefault('enabled', True)
            self.config['malicious_packages'].setdefault('auto_prohibit', True)

            # Gap A fix: ensure scoring.thresholds always has defaults so a
            # config.yaml missing the section never raises a KeyError downstream.
            self.config['scoring'].setdefault('thresholds', {
                'critical': 90,
                'high':     80,
                'medium':   70,
                'low':      60,
            })

            # Gap D fix: warn when scoring weights don't sum to 100 so
            # misconfiguration is surfaced early rather than silently skewing scores.
            _weights = self.config['scoring']['weights']
            _weight_total = sum(_weights.values())
            if _weights and _weight_total != 100:
                warnings.warn(
                    f"scoring.weights sum to {_weight_total}, expected 100; "
                    "scores may not be on a 0-100 scale",
                    UserWarning,
                    stacklevel=2,
                )

            # Environment variable overrides (higher priority than config.yaml)
            if os.environ.get('GITHUB_TOKEN'):
                self.config['github']['token'] = os.environ['GITHUB_TOKEN']
            if os.environ.get('NVD_API_KEY'):
                self.config['nvd']['api_key'] = os.environ['NVD_API_KEY']

            # Warn about placeholder credentials
            if self.config['github']['token'].startswith('<<'):
                logger.warning("GitHub token is a placeholder - API calls will be unauthenticated")
            if self.config['nvd']['api_key'].startswith('<<'):
                logger.warning("NVD API key is a placeholder - rate limits will be stricter")

        except Exception as e:
            logger.error("Config loading failed: %s", e)
            self.config = {}
            raise RuntimeError(f"Cannot start: config loading failed ({e})") from e


# Main Scorer Implementation
class OSSScorer:
    def __init__(self):
        self.config = OSSConfig().config
        self._last_request_time: float = 0.0
        self.github_provider = GitHubProvider(self.config)
        self.scorecard_provider = ScorecardProvider(self.config)
        self.framework = self.create_oss_framework()
        self.proprietary = self.create_proprietary_additions()

    def create_oss_framework(self):
        weights = self.config['scoring']['weights']
        thresholds = self.config['scoring']['thresholds']
        data = [
            ["1. PROJECT ACTIVITY", f"{weights['activity']}%", "", ""],
            ["  a. Commit Frequency", "10%", "0-100", "Daily=100, Weekly=80, Monthly=60, Quarterly=30, Yearly=10"],
            ["  b. Issue Resolution Time", "8%", "0-100", "<24h=100, <7d=80, <30d=60, >30d=20"],
            ["  c. Release Cadence", "7%", "0-100", "Monthly=100, Quarterly=80, Biannual=50, Yearly=20"],
            ["  d. Maintainer Response Rate", "5%", "0-100", ">90%=100, 70-90%=75, 50-70%=50, <50%=20"],

            ["2. CONTRIBUTOR TRUSTWORTHINESS", f"{weights['trust']}%", "", ""],
            ["  a. Maintainer Identity", "6%", "0-100", "Corp=100, Verified Individual=80, Anonymous=50, New Anonymous=20"],
            ["  b. Contributor Diversity", "5%", "0-100", ">10=100, 5-10=75, 2-5=50, Single=30"],
            ["  c. Geopolitical Risk", "9%", "0-100", "Multi-democratic=100, Low-risk=80, Partial high-risk=40, Majority high=10"],

            ["3. SECURITY POSTURE", f"{weights['security']}%", "", ""],
            ["  a. CVE History (3yr)", "12%", "0-100", "None=100, Low=80, Medium=50, High=10"],
            ["  b. CVE Response Time", "8%", "0-100", "<7d=100, <30d=80, <90d=60, >90d=20"],
            ["  c. Security Practices", "10%", "0-100", "Policy+Bounty=100, Policy=80, Some docs=50, None=10"],
            ["  d. Dependency Security", "5%", "0-100", "All updated=100, <3 minor=80, Some old=40, Vulnerable=0"],

            ["4. COMMUNITY & ADOPTION", f"{weights['community']}%", "", ""],
            ["  a. Active Usage", "6%", "0-100", ">1M/wk=100, 100K-1M=80, 10K-100K=60, <10K=30"],
            ["  b. Enterprise Adoption", "4%", "0-100", "F500=100, Tech firms=80, Some commercial=50, Individual=20"],
            ["  c. Community Engagement", "5%", "0-100", "Active forums=100, Regular issues=80, Some questions=50, Little interaction=20"],

            ["TOTAL SCORE", "100%", "0-100",
             f"A={thresholds['critical']}-100, B={thresholds['high']}-89, "
             f"C={thresholds['medium']}-79, D={thresholds['low']}-69, F<60"]
        ]
        return pd.DataFrame(data, columns=["Metric", "Weight", "Score Range", "Guidance"])

    def create_proprietary_additions(self):
        # Risk Heat Mapping
        risk_heat = [
            ["Mission Critical", "Low Risk (A-B)", "APPROVED", "Auto-approval with monitoring"],
            ["Mission Critical", "Medium Risk (C)", "REVIEW BOARD", "Requires CISO approval"],
            ["Mission Critical", "High Risk (D-F)", "PROHIBITED", "No exceptions permitted"],
            ["Business Critical", "Low Risk (A-B)", "APPROVED", "Standard approval"],
            ["Business Critical", "Medium Risk (C)", "MITIGATION REQ", "Compensating controls needed"],
            ["Business Critical", "High Risk (D-F)", "PROHIBITED", "Allowed only with VP waiver"],
            ["Non-Critical", "Low Risk (A-B)", "AUTO-APPROVED", "No review required"],
            ["Non-Critical", "Medium Risk (C)", "APPROVED", "Team lead approval"],
            ["Non-Critical", "High Risk (D-F)", "MITIGATION REQ", "Monthly review required"]
        ]
        risk_heat_df = pd.DataFrame(risk_heat, columns=["Application Criticality", "Risk Level", "Approval Status", "Notes"])

        # Geopolitical Risk Matrix
        multipliers = self.config['risk']['maintainer_risk_multipliers']
        geo_risk = [
            ["Corporate Entity", "US/EU/5EYES", 5, multipliers['corporate'], "Low risk multiplier"],
            ["Corporate Entity", "Other Democracies", 10, multipliers['corporate'] * 1.2, "Medium risk multiplier"],
            ["Corporate Entity", "High-Risk Nations", 50, multipliers['corporate'] * 2.0, "High risk multiplier"],
            ["Verified Individual", "US/EU/5EYES", 10, multipliers['verified_individual'], "Medium risk multiplier"],
            ["Verified Individual", "Other Democracies", 20, multipliers['verified_individual'] * 1.25, "Elevated risk multiplier"],
            ["Verified Individual", "High-Risk Nations", 75, multipliers['verified_individual'] * 2.5, "Very high risk multiplier"],
            ["Anonymous", "US/EU/5EYES", 30, multipliers['anonymous'], "High baseline risk"],
            ["Anonymous", "Other Democracies", 50, multipliers['anonymous'] * 1.5, "Very high baseline risk"],
            ["Anonymous", "High-Risk Nations", 100, multipliers['anonymous'] * 3.0, "Extreme risk - avoid"]
        ]
        geo_risk_df = pd.DataFrame(geo_risk, columns=["Maintainer Type", "Location", "Risk Points", "Weight Multiplier", "Notes"])

        return {
            "Risk_Heat_Mapping": risk_heat_df,
            "Geopolitical_Risk_Matrix": geo_risk_df
        }

    def _parse_github_owner_repo(self, url: str) -> tuple:
        """Extract (owner, repo) from a GitHub URL, raising ValueError on bad input."""
        parsed = urlparse(url.rstrip('/'))
        if parsed.netloc not in ('github.com', 'www.github.com'):
            raise ValueError(f"Not a GitHub URL: {url!r}")
        parts = [p for p in parsed.path.split('/') if p]
        if len(parts) < 2:
            raise ValueError(f"Cannot extract owner/repo from URL: {url!r}")
        repo_name = parts[-1]
        if repo_name.endswith('.git'):
            repo_name = repo_name[:-4]
        return parts[-2], repo_name

    def _build_headers(self, service: str) -> dict:
        """Build authentication headers for GitHub or NVD API requests."""
        if service == 'github' and self.config.get('github', {}).get('token'):
            return {'Authorization': f'token {self.config["github"]["token"]}'}
        if service == 'nvd' and self.config.get('nvd', {}).get('api_key'):
            return {'apiKey': self.config['nvd']['api_key']}
        return {}

    def _rate_limited_get(
        self,
        url: str,
        headers: dict,
        timeout: int,
        params: dict | None = None,
    ) -> requests.Response:
        """Perform a GET request, sleeping to honour the configured rate limit."""
        rate_limit = self.config.get('nvd', {}).get('rate_limit', 5)
        min_interval = 1.0 / rate_limit
        elapsed = time.monotonic() - self._last_request_time
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        self._last_request_time = time.monotonic()
        return requests.get(url, headers=headers, timeout=timeout, params=params)

    def get_github_metrics(self, repo_url: str) -> dict | None:
        """Fetch live GitHub metrics using the provider contract."""
        response = self.github_provider.fetch(repo_url)
        if response.is_success():
            return {
                'status': response.status.value,
                'fetched_at': response.fetched_at,
                **response.data,
            }
        return {
            'status': response.status.value,
            'fetched_at': response.fetched_at,
            'error': response.error.to_dict() if response.error else None,
        }

    def check_cves(self, package_name: str, ecosystem: str = "npm") -> dict:
        """Query NVD v2 API for CVEs then enrich each one with an EPSS score.

        Returns a dict with severity-band counts, EPSS-based counts, the
        highest observed EPSS value, and the full list of parsed CVE objects.
        All counts cover the past 3 years only.
        """
        _empty = {
            'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0,
            'epss_high': 0, 'max_epss': 0.0, 'cves': [],
            'last_updated': None,
            'status': 'error',
            'error': None,
        }

        try:
            since = (datetime.now(timezone.utc) - timedelta(days=_CVE_LOOKBACK_DAYS)).strftime(
                '%Y-%m-%dT00:00:00.000'
            )
            params = {
                'keywordSearch': package_name,
                'resultsPerPage': 50,
                'pubStartDate': since,
            }
            response = self._rate_limited_get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                headers=self._build_headers('nvd'),
                timeout=self.config['github']['timeout'],
                params=params,
            )

            if response.status_code != 200:
                logger.warning("NVD API returned %s for %s", response.status_code, package_name)
                _empty['error'] = f"HTTP {response.status_code}"
                return _empty

            parsed = []
            for item in response.json().get('vulnerabilities', []):
                cve_obj = item.get('cve', {})
                cve_id = cve_obj.get('id', '')
                metrics = cve_obj.get('metrics', {})

                # Prefer CVSSv3.1 → v3.0 → v2 for severity
                severity = 'UNKNOWN'
                base_score = 0.0
                for key in ('cvssMetricV31', 'cvssMetricV30'):
                    bucket = metrics.get(key, [])
                    if bucket:
                        cvss = bucket[0].get('cvssData', {})
                        severity = cvss.get('baseSeverity', 'UNKNOWN').upper()
                        base_score = float(cvss.get('baseScore', 0))
                        break
                else:
                    bucket = metrics.get('cvssMetricV2', [])
                    if bucket:
                        severity = bucket[0].get('baseSeverity', 'UNKNOWN').upper()
                        base_score = float(bucket[0].get('cvssData', {}).get('baseScore', 0))

                parsed.append({
                    'id': cve_id,
                    'severity': severity,
                    'base_score': base_score,
                    'epss': 0.0,
                    'epss_percentile': 0.0,
                })

        except requests.RequestException as e:
            logger.error("NVD API error for %s: %s", package_name, str(e))
            _empty['error'] = str(e)
            return _empty

        if not parsed:
            return {
                'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0,
                'epss_high': 0, 'max_epss': 0.0, 'cves': [],
                'last_updated': datetime.now().isoformat(),
                'status': 'success',
                'error': None,
            }

        # Enrich with EPSS scores (batched, best-effort)
        epss_map = self.get_epss_scores([c['id'] for c in parsed if c['id']])
        for cve in parsed:
            if cve['id'] in epss_map:
                cve['epss'] = epss_map[cve['id']]['epss']
                cve['epss_percentile'] = epss_map[cve['id']]['percentile']

        return {
            'total': len(parsed),
            'critical': sum(1 for c in parsed if c['severity'] == 'CRITICAL'),
            'high':     sum(1 for c in parsed if c['severity'] == 'HIGH'),
            'medium':   sum(1 for c in parsed if c['severity'] == 'MEDIUM'),
            'low':      sum(1 for c in parsed if c['severity'] == 'LOW'),
            'epss_high': sum(1 for c in parsed if c['epss'] >= _EPSS_HIGH_THRESHOLD),
            'max_epss':  round(max((c['epss'] for c in parsed), default=0.0), 4),
            'cves':      parsed,
            'last_updated': datetime.now().isoformat(),
            'status': 'success',
            'error': None,
        }

    def get_epss_scores(self, cve_ids: list[str]) -> dict[str, dict]:
        """Fetch EPSS exploit-probability scores from FIRST.org for a list of CVE IDs.

        Calls the free FIRST API (no key required) in batches of 30.
        Returns {cve_id: {'epss': float, 'percentile': float}}.
        """
        if not cve_ids:
            return {}

        results: dict[str, dict] = {}
        for i in range(0, len(cve_ids), 30):
            batch = cve_ids[i:i + 30]
            try:
                resp = requests.get(
                    "https://api.first.org/data/1.0/epss",
                    params={'cve': ','.join(batch)},
                    timeout=self.config.get('epss', {}).get('timeout', 10)
                )
                if resp.status_code == 200:
                    for item in resp.json().get('data', []):
                        cid = item.get('cve', '')
                        if cid:
                            results[cid] = {
                                'epss': float(item.get('epss', 0)),
                                'percentile': float(item.get('percentile', 0)),
                            }
                else:
                    logger.warning("EPSS API returned %s for batch [%s...]", resp.status_code, batch[0])
            except requests.RequestException as e:
                logger.warning("EPSS API error for batch [%s...]: %s", batch[0], e)

        return results

    def _resolve_osv_ecosystem(self, ecosystem: str) -> str | None:
        """Map a registry or language name to an OSV.dev ecosystem identifier.

        Unlike _resolve_registry(), this ignores the 'enabled' flag so that
        OSV security checks run even when download counting is disabled for a
        registry (e.g. Maven has no public download API but OSV covers it).
        """
        key = ecosystem.lower().strip()

        # Direct registry-name match in OSV map
        if key in _OSV_ECOSYSTEM_MAP:
            return _OSV_ECOSYSTEM_MAP[key]

        # Language alias scan across all registries (ignores enabled flag)
        for reg_name, reg_cfg in self.config.get('registries', {}).items():
            if not isinstance(reg_cfg, dict):
                continue
            if key in [l.lower() for l in reg_cfg.get('languages', [])]:
                return _OSV_ECOSYSTEM_MAP.get(reg_name)

        return None

    def check_osv(self, package_name: str, ecosystem: str = "npm") -> dict:
        """Query OSV.dev for known vulnerabilities and malicious package flags.

        OSV aggregates advisories from NVD, GitHub Security Advisories (GHSA),
        and the ossf/malicious-packages dataset.  Advisories with a MAL- prefix
        indicate packages confirmed as intentionally malicious (typosquatting,
        backdoors, supply-chain attacks).

        Returns a dict with:
          is_malicious      – True if any MAL- advisory was found
          malicious_ids     – list of MAL- advisory IDs
          malicious_count   – number of MAL- advisories
          extra_advisories  – GHSA/ecosystem advisories without a CVE alias
                              (supplements the NVD/EPSS pipeline)
          total             – total advisory count
          advisories        – full list (id, summary, is_malicious, aliases)
        """
        _base: dict = {
            'total': 0, 'malicious_count': 0, 'is_malicious': False,
            'malicious_ids': [], 'extra_advisories': 0, 'advisories': [],
            'last_updated': None,
        }
        # Network/provider failure template — used for actual errors only.
        _empty: dict = {**_base, 'status': 'error', 'error': None}

        if not self.config.get('osv', {}).get('enabled', True):
            # OSV intentionally disabled — not a provider error.
            return {**_base, 'status': 'disabled', 'error': None}

        osv_ecosystem = self._resolve_osv_ecosystem(ecosystem)
        if not osv_ecosystem:
            logger.info("No OSV ecosystem mapping for %r — skipping OSV check", ecosystem)
            # Ecosystem has no OSV mapping — not a network failure.
            return {**_base, 'status': 'unsupported', 'error': None}

        # Whether to honour MAL- advisory flags (requires malicious_packages.enabled)
        check_malicious = self.config.get('malicious_packages', {}).get('enabled', True)

        timeout = self.config.get('osv', {}).get('timeout', 10)
        try:
            resp = requests.post(
                "https://api.osv.dev/v1/query",
                json={"package": {"name": package_name, "ecosystem": osv_ecosystem}},
                timeout=timeout,
            )
            if resp.status_code != 200:
                logger.warning(
                    "OSV API returned %s for %s/%s", resp.status_code,
                    osv_ecosystem, package_name
                )
                _empty['error'] = f"HTTP {resp.status_code}"
                return _empty

            advisories: list[dict] = []
            malicious_ids: list[str] = []
            extra_count = 0

            for v in resp.json().get('vulns', []):
                vid = v.get('id', '')
                aliases = v.get('aliases', [])
                is_mal = check_malicious and vid.startswith('MAL-')

                advisories.append({
                    'id': vid,
                    'summary': v.get('summary', ''),
                    'is_malicious': is_mal,
                    'aliases': aliases,
                })

                if is_mal:
                    malicious_ids.append(vid)
                elif (not vid.startswith('CVE-')
                      and not vid.startswith('MAL-')
                      and not any(a.startswith('CVE-') for a in aliases)):
                    # GHSA or ecosystem advisory not already captured by NVD pipeline
                    extra_count += 1

            return {
                'total': len(advisories),
                'malicious_count': len(malicious_ids),
                'is_malicious': len(malicious_ids) > 0,
                'malicious_ids': malicious_ids,
                'extra_advisories': extra_count,
                'advisories': advisories,
                'last_updated': datetime.now().isoformat(),
                'status': 'success',
                'error': None,
            }

        except requests.RequestException as e:
            logger.error("OSV API error for %s/%s: %s", osv_ecosystem, package_name, str(e))
            _empty['error'] = str(e)
            return _empty

    def _resolve_registry(self, ecosystem: str) -> str | None:
        """Map an ecosystem or language name to an enabled registry name.

        Tries a direct key match first (e.g. 'npm' → 'npm'), then falls back
        to scanning each registry's 'languages' list.  Returns None when the
        ecosystem is unknown or the matching registry is disabled.
        """
        key = ecosystem.lower().strip()
        registries = self.config.get('registries', {})

        # Direct match — caller already knows the registry name
        if key in registries:
            if registries[key].get('enabled', True):
                return key
            logger.info("Registry %r is disabled in config", key)
            return None

        # Language alias match
        for reg_name, reg_cfg in registries.items():
            if not isinstance(reg_cfg, dict):
                continue
            langs = [l.lower() for l in reg_cfg.get('languages', [])]
            if key in langs:
                if reg_cfg.get('enabled', True):
                    return reg_name
                logger.info("Registry %r (matched via language %r) is disabled", reg_name, key)
                return None

        logger.info("No registry found for ecosystem %r", ecosystem)
        return None

    def get_download_count(self, package_name: str, ecosystem: str) -> dict:
        """Fetch weekly download statistics from the appropriate package registry.

        The registry is resolved from config via ecosystem/language name.
        Returns a dict with keys: weekly_downloads (int or None), period (str),
        registry (str), status (str), error (str or None).
        On unknown ecosystem or fetch failure, returns a dict with
        weekly_downloads=None and status='error' so callers can detect failures.
        All periods are normalised to a weekly equivalent where possible.
        """
        registry = self._resolve_registry(ecosystem)
        if registry is None:
            return {
                'weekly_downloads': None,
                'period': 'unknown',
                'registry': ecosystem,
                'status': 'error',
                'error': f"No registry mapping for ecosystem {ecosystem!r}",
            }

        timeout = self.config['registries'][registry].get('timeout', 10)
        try:
            if registry == 'npm':
                result = self._fetch_npm(package_name, timeout)
            elif registry == 'pypi':
                result = self._fetch_pypi(package_name, timeout)
            elif registry == 'rubygems':
                result = self._fetch_rubygems(package_name, timeout)
            elif registry == 'crates':
                result = self._fetch_crates(package_name, timeout)
            elif registry == 'nuget':
                result = self._fetch_nuget(package_name, timeout)
            elif registry == 'packagist':
                result = self._fetch_packagist(package_name, timeout)
            else:
                logger.info("No download fetcher implemented for registry %r", registry)
                return {
                    'weekly_downloads': None,
                    'period': 'unknown',
                    'registry': registry,
                    'status': 'error',
                    'error': f"No fetcher for registry {registry!r}",
                }
            result.setdefault('status', 'success')
            result.setdefault('error', None)
            return result
        except requests.RequestException as e:
            logger.error("Download count error [%s/%s]: %s", registry, package_name, str(e))
            return {
                'weekly_downloads': None,
                'period': 'unknown',
                'registry': registry,
                'status': 'error',
                'error': str(e),
            }

    def _fetch_npm(self, package: str, timeout: int) -> dict:
        """Weekly downloads from the npm registry API."""
        resp = requests.get(
            f"https://api.npmjs.org/downloads/point/last-week/{package}",
            timeout=timeout
        )
        resp.raise_for_status()
        return {
            'weekly_downloads': int(resp.json().get('downloads', 0)),
            'period': 'weekly',
            'registry': 'npm',
        }

    def _fetch_pypi(self, package: str, timeout: int) -> dict:
        """Weekly downloads from the PyPI stats API."""
        resp = requests.get(
            f"https://pypistats.org/api/packages/{package.lower()}/recent",
            timeout=timeout
        )
        resp.raise_for_status()
        return {
            'weekly_downloads': int(resp.json().get('data', {}).get('last_week', 0)),
            'period': 'weekly',
            'registry': 'pypi',
        }

    def _fetch_rubygems(self, package: str, timeout: int) -> dict:
        """Estimated weekly downloads from RubyGems (version total ÷ 52)."""
        resp = requests.get(
            f"https://rubygems.org/api/v1/gems/{package}.json",
            timeout=timeout
        )
        resp.raise_for_status()
        version_total = int(resp.json().get('version_downloads', 0))
        return {
            'weekly_downloads': version_total // 52,
            'period': 'estimated_weekly',
            'registry': 'rubygems',
        }

    def _fetch_crates(self, package: str, timeout: int) -> dict:
        """Estimated weekly downloads from crates.io (90-day count ÷ 13)."""
        resp = requests.get(
            f"https://crates.io/api/v1/crates/{package}",
            headers={'User-Agent': self.config.get('geocoding', {}).get('user_agent',
                                                                        'OSSPolicyGuard/1.0')},
            timeout=timeout
        )
        resp.raise_for_status()
        recent = int(resp.json().get('crate', {}).get('recent_downloads', 0) or 0)
        return {
            'weekly_downloads': recent // 13,
            'period': 'estimated_weekly',
            'registry': 'crates',
        }

    def _fetch_nuget(self, package: str, timeout: int) -> dict:
        """Estimated weekly downloads from NuGet (total ÷ 104-week lifetime)."""
        resp = requests.get(
            "https://azuresearch-usnc.nuget.org/query",
            params={'q': f'packageid:{package}', 'take': 1},
            timeout=timeout
        )
        resp.raise_for_status()
        data = resp.json().get('data', [])
        total = int(data[0].get('totalDownloads', 0)) if data else 0
        return {
            'weekly_downloads': total // 104,  # assume 2-year average lifetime
            'period': 'estimated_weekly',
            'registry': 'nuget',
        }

    def _fetch_packagist(self, package: str, timeout: int) -> dict:
        """Estimated weekly downloads from Packagist (monthly ÷ 4).

        Requires 'vendor/package' format for package_name.
        """
        if '/' not in package:
            logger.warning(
                "Packagist requires vendor/package format, got %r — skipping", package
            )
            return {'weekly_downloads': 0, 'period': 'unknown', 'registry': 'packagist'}
        resp = requests.get(
            f"https://packagist.org/packages/{package}.json",
            timeout=timeout
        )
        resp.raise_for_status()
        monthly = int(
            resp.json().get('package', {}).get('downloads', {}).get('monthly', 0) or 0
        )
        return {
            'weekly_downloads': monthly // 4,
            'period': 'estimated_weekly',
            'registry': 'packagist',
        }

    def get_scorecard(self, repo_url: str) -> dict | None:
        """Fetch OpenSSF Scorecard security score using the provider contract."""
        # Gap C fix: honour the scorecard.enabled flag before making any API call.
        if not self.config.get('scorecard', {}).get('enabled', True):
            return None
        response = self.scorecard_provider.fetch(repo_url)
        if response.is_success():
            return {
                'status': response.status.value,
                'fetched_at': response.fetched_at,
                **response.data,
            }
        return {
            'status': response.status.value,
            'fetched_at': response.fetched_at,
            'error': response.error.to_dict() if response.error else None,
        }

    def _geocode_location(self, location_str: str) -> str:
        """Convert a free-text location string to an ISO-3166-1 alpha-2 country code.

        Uses a fast local lookup first, then falls back to the Nominatim geocoding
        API (OpenStreetMap, free, no key required). Returns '' when unknown.
        """
        if not location_str:
            return ''

        loc_lower = location_str.lower().strip()

        # Fast path: check every token/phrase in the lookup map
        for pattern, code in _LOCATION_COUNTRY_MAP.items():
            if pattern in loc_lower:
                return code

        # Slow path: call Nominatim
        geo_cfg = self.config.get('geocoding', {})
        if not geo_cfg.get('enabled', True):
            return ''
        nominatim_url = geo_cfg.get('nominatim_url', 'https://nominatim.openstreetmap.org')
        user_agent = geo_cfg.get('user_agent', 'OSSPolicyGuard/1.0')
        try:
            resp = requests.get(
                f"{nominatim_url}/search",
                params={'q': location_str, 'format': 'json', 'limit': 1, 'addressdetails': 1},
                headers={'User-Agent': user_agent},
                timeout=5
            )
            if resp.status_code == 200:
                results = resp.json()
                if results:
                    return results[0].get('address', {}).get('country_code', '').upper()
        except requests.RequestException:
            pass  # geocoding is best-effort

        return ''

    def get_contributor_locations(self, contributors_url: str) -> list[dict]:
        """Fetch top contributors and geocode their profile locations.

        Returns a list of dicts with keys: login, contributions, location,
        company, country_code.
        """
        geo_cfg = self.config.get('geocoding', {})
        if not geo_cfg.get('enabled', True):
            return []

        top_n = geo_cfg.get('max_contributors', 10)

        try:
            headers = self._build_headers('github')
            response = self._rate_limited_get(
                f"{contributors_url}?per_page={top_n}",
                headers=headers,
                timeout=self.config['github']['timeout']
            )
            response.raise_for_status()
            contributors_raw = response.json()
        except requests.RequestException as e:
            logger.error("Contributors API error: %s", e)
            return []

        results = []
        for contrib in contributors_raw[:top_n]:
            login = contrib.get('login', '')
            commit_count = contrib.get('contributions', 0)
            location = ''
            company = ''

            try:
                user_resp = self._rate_limited_get(
                    f"https://api.github.com/users/{login}",
                    headers=headers,
                    timeout=self.config['github']['timeout']
                )
                user_resp.raise_for_status()
                user_data = user_resp.json()
                location = user_data.get('location') or ''
                company = (user_data.get('company') or '').lstrip('@')
            except requests.RequestException as e:
                logger.warning("Could not fetch profile for contributor %s: %s", login, e)

            results.append({
                'login': login,
                'contributions': commit_count,
                'location': location,
                'company': company,
                'country_code': self._geocode_location(location),
            })

        return results


# Visualization and Interaction
class OSSVisualizer:
    def __init__(self, scorer):
        self.scorer = scorer

    def create_dashboard(self, project_data: dict, show: bool = True):
        """Create a matplotlib dashboard. Pass show=False to suppress display (useful in tests)."""
        fig = plt.figure(figsize=(14, 8))

        # Score Breakdown
        if 'scores' in project_data:
            scores = project_data['scores']
            plt.subplot(1, 2, 1)
            plt.bar(scores.keys(), scores.values(), color=['#4CAF50', '#FFC107', '#F44336', '#2196F3'])
            plt.title("Component Score Breakdown")
            plt.ylabel("Score (0-100)")
            plt.ylim(0, 100)
            plt.xticks(rotation=45)

            # Risk Visualization
            plt.subplot(1, 2, 2)
            risk_level = project_data.get('risk_level', 'Medium')
            risk_colors = {
                'Low': '#4CAF50',
                'Medium-Low': '#8BC34A',
                'Medium': '#FFC107',
                'Medium-High': '#FF9800',
                'High': '#F44336'
            }
            plt.pie(
                [project_data['total_score'], 100 - project_data['total_score']],
                labels=['Score', 'Risk Gap'],
                colors=[risk_colors.get(risk_level, '#FFC107'), '#E0E0E0'],
                startangle=90
            )
            plt.title(f"Risk Level: {risk_level}")

        plt.tight_layout()
        if show:
            plt.show()

        # Display framework as table
        display(Markdown("### Scoring Framework"))
        display(self.scorer.framework.style.set_caption("Scoring Framework"))

        return fig

    def interactive_selector(self):
        """Jupyter interactive widget"""
        dropdown = Dropdown(
            options=self.scorer.proprietary['Risk_Heat_Mapping']['Application Criticality'].unique(),
            description='App Criticality:'
        )

        output = widgets.Output()

        def update_requirements(criticality):
            with output:
                output.clear_output()
                display(Markdown(f"### Approval Requirements for {criticality}"))
                reqs = self.scorer.proprietary['Risk_Heat_Mapping'][
                    self.scorer.proprietary['Risk_Heat_Mapping']['Application Criticality'] == criticality
                ]
                display(reqs.style.set_properties(**{
                    'background-color': '#f8f9fa',
                    'border': '1px solid #dee2e6'
                }))

        interact(update_requirements, criticality=dropdown)
        display(output)


# Workflow Automation
class OSSWorkflow:
    def __init__(self, scorer):
        self.scorer = scorer
        self.config = OSSConfig().config

    def evaluate_component(self, component_data: dict) -> dict:
        """Full evaluation pipeline"""
        if not isinstance(component_data, dict):
            raise TypeError(f"component_data must be a dict, got {type(component_data).__name__}")

        criticality = component_data.get('criticality', 'Non-Critical')
        if criticality not in _VALID_CRITICALITY:
            raise ValueError(
                f"Invalid criticality {criticality!r}. Must be one of: {sorted(_VALID_CRITICALITY)}"
            )

        results = {
            **component_data,
            'timestamp': datetime.now().isoformat(),
            'analysis_version': '1.0',
            'config_used': {
                'weights': self.config['scoring']['weights'],
                'thresholds': self.config['scoring']['thresholds']
            }
        }

        # GitHub metrics
        if 'repo_url' in component_data:
            gh_metrics = self.scorer.get_github_metrics(component_data['repo_url'])
            if gh_metrics:
                results['github_metrics'] = gh_metrics

            # OpenSSF Scorecard
            scorecard = self.scorer.get_scorecard(component_data['repo_url'])
            if scorecard:
                results['scorecard_data'] = scorecard

            # Contributor geolocation (requires contributors_url from github_metrics)
            contributors_url = (results.get('github_metrics') or {}).get('contributors_url', '')
            if contributors_url:
                locations = self.scorer.get_contributor_locations(contributors_url)
                if locations:
                    results['contributor_locations'] = locations

        # Package registry: download count + CVE check
        if 'package_name' in component_data:
            # Download count — requires ecosystem or language to resolve registry
            ecosystem = (
                component_data.get('ecosystem')
                or component_data.get('language', '')
            )
            if ecosystem:
                dl_data = self.scorer.get_download_count(
                    component_data['package_name'], ecosystem
                )
                # Always store download_data so from_legacy() can detect failures
                # via the explicit status field rather than key absence.
                results['download_data'] = dl_data
            else:
                logger.info(
                    "No 'ecosystem' or 'language' in component_data — "
                    "download count skipped for %s", component_data['package_name']
                )

            cve_data = self.scorer.check_cves(component_data['package_name'])
            results['cve_data'] = cve_data

            # Vulnerability + malicious-package check via OSV / ossf/malicious-packages
            if ecosystem:
                osv_data = self.scorer.check_osv(component_data['package_name'], ecosystem)
                results['osv_data'] = osv_data
            else:
                logger.info(
                    "No 'ecosystem' or 'language' in component_data — "
                    "OSV check skipped for %s", component_data['package_name']
                )

        # ------------------------------------------------------------------
        # Provider-health audit — detect failed security data sources before
        # computing scores.  When NVD or OSV cannot be reached the security
        # sub-score starts at 100 (no CVEs seen ≠ no CVEs exist); allowing
        # that to produce APPROVED would violate the project's audit contract.
        # ------------------------------------------------------------------
        provider_warnings: list[str] = []
        nvd_status = results.get('cve_data', {}).get('status', 'success')
        osv_status = results.get('osv_data', {}).get('status', 'success')

        if nvd_status == 'error':
            provider_warnings.append(
                "NVD provider unavailable — CVE data is incomplete; "
                "security score may be overstated"
            )
        if osv_status == 'error':
            provider_warnings.append(
                "OSV provider unavailable — vulnerability/malicious-package "
                "check is incomplete"
            )

        insufficient_data = bool(provider_warnings)
        if provider_warnings:
            existing = results.get('warnings', [])
            results['warnings'] = list(existing) + provider_warnings

        # Calculate scores
        scores = {
            'activity': self._calculate_activity_score(results),
            'security': self._calculate_security_score(results),
            'trust': self._calculate_trust_score(results),
            'community': self._calculate_community_score(results)
        }

        # Apply weights
        weighted_scores = {
            k: v * (self.config['scoring']['weights'][k] / 100)
            for k, v in scores.items()
        }
        total_score = sum(weighted_scores.values())

        approval = self._determine_approval(total_score, criticality)

        # If required security providers failed the score is unreliable — a
        # clean-looking score must not silently become an approval.
        if insufficient_data and approval == 'APPROVED':
            approval = 'REVIEW'

        results.update({
            'scores': scores,
            'weighted_scores': weighted_scores,
            'total_score': total_score,
            'approval': approval,
            'insufficient_data': insufficient_data,
            'risk_level': self._get_risk_level(total_score)
        })

        # Optional geo-compliance assessment.  Results are stored under a
        # separate 'compliance' key and never modify the technical trust score.
        geo_cfg = self.config.get('risk', {}).get('geo_compliance', {})
        if geo_cfg.get('enabled', False) and 'contributor_locations' in results:
            geo_score = self._calculate_geo_risk_score(results['contributor_locations'])
            if geo_score >= 70:
                geo_status = 'OK'
            elif geo_score >= 40:
                geo_status = 'REVIEW'
            else:
                geo_status = 'ALERT'
            results['compliance'] = {
                'geo_jurisdiction': {
                    'score': geo_score,
                    'status': geo_status,
                    'affects_technical_score': False,
                }
            }

        # Malicious package: force PROHIBITED regardless of score or criticality
        if (results.get('osv_data', {}).get('is_malicious')
                and self.config.get('malicious_packages', {}).get('auto_prohibit', True)):
            results['is_malicious'] = True
            results['approval'] = 'PROHIBITED'
            results['risk_level'] = 'High'

        return results

    def _calculate_activity_score(self, results: dict) -> float:
        """Calculate activity score (0-100) based on days since last commit."""
        if 'github_metrics' not in results:
            return 40  # unknown - penalise but don't zero out
        last_commit_str = results['github_metrics'].get('last_commit', '')
        if not last_commit_str:
            return 40
        try:
            last_commit = datetime.fromisoformat(last_commit_str.rstrip('Z'))
            if last_commit.tzinfo is None:
                last_commit = last_commit.replace(tzinfo=timezone.utc)
            days_stale = (datetime.now(timezone.utc) - last_commit).days
        except ValueError:
            return 40
        if days_stale < 7:
            return 100
        if days_stale < 30:
            return 80
        if days_stale < 90:
            return 60
        if days_stale < 365:
            return 30
        return 10

    def _calculate_security_score(self, results: dict) -> float:
        """Calculate security score (0-100) using EPSS-weighted CVE deductions + OpenSSF Scorecard.

        Each CVE deducts points based on its EPSS exploit-probability:
          EPSS ≥ 0.5  (actively weaponised)    → -15 pts
          EPSS 0.1–0.5 (moderate risk)          → -8 pts
          EPSS < 0.1  (theoretical)             → -2 pts
          No EPSS + CVSS CRITICAL               → -10 pts
          No EPSS + CVSS HIGH                   → -5 pts
          No EPSS + CVSS MEDIUM                 → -2 pts

        When an OpenSSF Scorecard is available it contributes 40% of the final
        score (covering CI hardening, code review, branch protection, etc.) and
        the EPSS/CVE component contributes the remaining 60%.
        """
        osv_data = results.get('osv_data', {})

        # Malicious package (ossf/malicious-packages via OSV) → immediate zero
        if (osv_data.get('is_malicious')
                and self.config.get('malicious_packages', {}).get('auto_prohibit', True)):
            return 0.0

        # Gap B fix: read EPSS thresholds from config so operators can tune them;
        # fall back to the module-level constants when not configured.
        _epss_cfg = self.config.get('epss', {})
        _epss_high = _epss_cfg.get('high_threshold', _EPSS_HIGH_THRESHOLD)
        _epss_med  = _epss_cfg.get('med_threshold',  _EPSS_MED_THRESHOLD)

        cve_score = 100.0
        for cve in results.get('cve_data', {}).get('cves', []):
            epss = cve.get('epss', 0.0)
            severity = cve.get('severity', 'UNKNOWN')
            if epss >= _epss_high:
                cve_score -= _DEDUCT_EPSS_HIGH
            elif epss >= _epss_med:
                cve_score -= _DEDUCT_EPSS_MED
            elif epss > 0:
                cve_score -= _DEDUCT_EPSS_LOW
            elif severity == 'CRITICAL':
                cve_score -= _DEDUCT_CVSS_CRITICAL
            elif severity == 'HIGH':
                cve_score -= _DEDUCT_CVSS_HIGH
            elif severity == 'MEDIUM':
                cve_score -= _DEDUCT_CVSS_MEDIUM
        cve_score = max(0.0, min(100.0, cve_score))

        # OSV extra advisories (GHSA/ecosystem-specific, not already in NVD)
        extra = osv_data.get('extra_advisories', 0)
        if extra > 0:
            deduction = self.config.get('osv', {}).get('extra_advisory_deduction', 3)
            max_pen = self.config.get('osv', {}).get('extra_advisory_max_penalty', 20)
            cve_score = max(0.0, cve_score - min(max_pen, extra * deduction))

        if 'scorecard_data' in results:
            sc_score = results['scorecard_data'].get('score')
            if sc_score is not None:
                scorecard_score = min(100.0, sc_score * 10)
                return round(0.6 * cve_score + 0.4 * scorecard_score, 1)
            # Scorecard provider failed (no 'score' key) — fall back to CVE-only score.

        return round(cve_score, 1)

    def _calculate_trust_score(self, results: dict) -> float:
        """Calculate trustworthiness score (0-100).

        The technical trust score is based solely on project maturity (fork
        count as a community-adoption proxy).  Contributor geography is NOT
        part of this score — it is evaluated separately in evaluate_component()
        and returned under ``compliance.geo_jurisdiction`` so that jurisdiction
        policy never silently changes the numeric package-risk score.
        """
        forks = (results.get('github_metrics') or {}).get('forks', 0)
        if forks > _FORKS_HIGH_THRESHOLD:
            maturity = 100.0
        elif forks > _FORKS_MED_THRESHOLD:
            maturity = 80.0
        elif forks > _FORKS_LOW_THRESHOLD:
            maturity = 60.0
        elif results.get('github_metrics'):
            maturity = 40.0
        else:
            maturity = 50.0  # no data at all — neutral

        return round(maturity, 1)

    def _calculate_geo_risk_score(self, contributors: list[dict]) -> float:
        """Score optional compliance risk from geocoded contributors.

        This is intentionally not part of the default security signal. It is only
        active when the caller opts into an explicit geo/compliance rule.
        """
        geo_cfg = self.config.get('risk', {}).get('geo_compliance', {})
        if not geo_cfg.get('enabled', False):
            return 50.0

        if not contributors:
            return 50.0

        high_risk_countries = set(geo_cfg.get('high_risk_countries', []))

        total_commits = sum(c.get('contributions', 0) for c in contributors)
        if total_commits == 0:
            return 50.0

        high_risk_commits = 0
        unknown_commits = 0
        for c in contributors:
            n = c.get('contributions', 0)
            code = c.get('country_code', '')
            if not code:
                unknown_commits += n
            elif code in high_risk_countries:
                high_risk_commits += n

        high_risk_frac = high_risk_commits / total_commits
        unknown_frac = unknown_commits / total_commits
        penalty = high_risk_frac + 0.2 * unknown_frac
        return round(max(0.0, 100.0 * (1 - penalty)), 1)

    def _calculate_community_score(self, results: dict) -> float:
        """Calculate community/adoption score (0-100).

        Blends two signals when both are available:
          - Weekly download count from the package registry (primary, 70%)
          - GitHub star count                              (secondary, 30%)

        Falls back to whichever signal is available; returns 40 when neither
        is present (unknown — penalised but not zeroed).
        """
        comm = self.config.get('scoring', {}).get('community', {})
        wh = comm.get('weekly_high', _STARS_HIGH_THRESHOLD * 100)
        wm = comm.get('weekly_med',  _STARS_MED_THRESHOLD * 100)
        wl = comm.get('weekly_low',  _STARS_LOW_THRESHOLD * 100)
        dl_w  = comm.get('download_weight', 0.7)
        star_w = comm.get('star_weight', 0.3)

        def _dl_score(weekly: int) -> float:
            if weekly > wh: return 100.0
            if weekly > wm: return 80.0
            if weekly > wl: return 60.0
            return 40.0

        def _star_score(stars: int) -> float:
            if stars > _STARS_HIGH_THRESHOLD: return 100.0
            if stars > _STARS_MED_THRESHOLD:  return 80.0
            if stars > _STARS_LOW_THRESHOLD:  return 60.0
            return 40.0

        weekly = (results.get('download_data') or {}).get('weekly_downloads')
        has_dl   = weekly is not None
        has_star = 'github_metrics' in results

        if has_dl and has_star:
            dl   = _dl_score(weekly)
            star = _star_score(results['github_metrics'].get('stars', 0))
            return round(dl_w * dl + star_w * star, 1)

        if has_dl:
            return _dl_score(weekly)

        if has_star:
            return _star_score(results['github_metrics'].get('stars', 0))

        return 40.0  # no data — penalised but not zero

    def _determine_approval(self, score: float, criticality: str) -> str:
        """Return one of three canonical decision strings: APPROVED, REVIEW, PROHIBITED.

        Thresholds come from config['scoring']['thresholds']:
          critical (default 90), high (default 80), medium (default 70), low (default 60).

        Mission Critical  : score ≥ critical → APPROVED; ≥ high → REVIEW; else PROHIBITED
        Business Critical : score ≥ high     → APPROVED; ≥ medium → REVIEW; else PROHIBITED
        Non-Critical      : score ≥ low      → APPROVED; else REVIEW (never PROHIBITED)

        A malicious-package flag overrides to PROHIBITED regardless of score; that
        check is applied upstream in evaluate_component().
        """
        t = self.config['scoring']['thresholds']
        if criticality == "Mission Critical":
            if score >= t['critical']:
                return "APPROVED"
            if score >= t['high']:
                return "REVIEW"
            return "PROHIBITED"
        if criticality == "Business Critical":
            if score >= t['high']:
                return "APPROVED"
            if score >= t['medium']:
                return "REVIEW"
            return "PROHIBITED"
        # Non-Critical — never PROHIBITED by score alone
        if score >= t['low']:
            return "APPROVED"
        return "REVIEW"

    def _get_risk_level(self, score: float) -> str:
        thresholds = self.config['scoring']['thresholds']
        if score >= thresholds['critical']:
            return "Low"
        if score >= thresholds['high']:
            return "Medium-Low"
        if score >= thresholds['medium']:
            return "Medium"
        if score >= thresholds['low']:
            return "Medium-High"
        return "High"


# Jupyter Notebook Helper
def init_oss_analysis():
    """Initialize all components for Jupyter Notebook"""
    try:
        config = OSSConfig()
        scorer = OSSScorer()
        workflow = OSSWorkflow(scorer)
        visualizer = OSSVisualizer(scorer)

        display(Markdown("## Open Source Security Scoring System"))
        display(Markdown(f"Loaded configuration with weights: {config.config['scoring']['weights']}"))

        return scorer, workflow, visualizer
    except Exception as e:
        logger.exception("Initialization failed")
        display(Markdown(f"### Error: {str(e)}"))
        raise
