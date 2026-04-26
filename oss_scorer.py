import os
import time
import logging
import yaml
import pandas as pd
import requests
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse
import matplotlib.pyplot as plt
from ipywidgets import interact, Dropdown
import ipywidgets as widgets
from IPython.display import display, Markdown
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(name)s %(levelname)s %(message)s'
)
logger = logging.getLogger(__name__)

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

    def _rate_limited_get(self, url: str, headers: dict, timeout: int) -> requests.Response:
        """Perform a GET request, sleeping to honour the configured rate limit."""
        rate_limit = self.config.get('nvd', {}).get('rate_limit', 5)
        min_interval = 1.0 / rate_limit
        elapsed = time.monotonic() - self._last_request_time
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        self._last_request_time = time.monotonic()
        return requests.get(url, headers=headers, timeout=timeout)

    def get_github_metrics(self, repo_url: str) -> dict | None:
        """Fetch live GitHub metrics using API"""
        try:
            owner, repo = self._parse_github_owner_repo(repo_url)
        except ValueError as exc:
            logger.error("Invalid repo URL: %s", exc)
            return None

        try:
            headers = self._build_headers('github')
            response = self._rate_limited_get(
                f'https://api.github.com/repos/{owner}/{repo}',
                headers=headers,
                timeout=self.config['github']['timeout']
            )
            response.raise_for_status()
            repo_data = response.json()

            return {
                'stars': repo_data.get('stargazers_count', 0),
                'forks': repo_data.get('forks_count', 0),
                'last_commit': repo_data.get('pushed_at', ''),
                'open_issues': repo_data.get('open_issues_count', 0),
                'contributors_url': repo_data.get('contributors_url', '')
            }
        except requests.RequestException as e:
            logger.error("GitHub API error for %s: %s", repo_url, e)
            return None

    def check_cves(self, package_name: str, ecosystem: str = "npm") -> dict:
        """Query NVD v2 API for CVEs then enrich each one with an EPSS score.

        Returns a dict with severity-band counts, EPSS-based counts, the
        highest observed EPSS value, and the full list of parsed CVE objects.
        All counts cover the past 3 years only.
        """
        _empty = {
            'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0,
            'epss_high': 0, 'max_epss': 0.0, 'cves': [],
            'last_updated': datetime.now().isoformat()
        }

        try:
            since = (datetime.utcnow() - timedelta(days=_CVE_LOOKBACK_DAYS)).strftime(
                '%Y-%m-%dT00:00:00.000'
            )
            response = self._rate_limited_get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                headers=self._build_headers('nvd'),
                timeout=self.config['github']['timeout']
            )
            # NVD v2 requires params via the URL; rebuild with params
            response = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={'keywordSearch': package_name, 'resultsPerPage': 50,
                        'pubStartDate': since},
                headers=self._build_headers('nvd'),
                timeout=self.config['github']['timeout']
            )

            if response.status_code != 200:
                logger.warning("NVD API returned %s for %s", response.status_code, package_name)
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
            logger.error("NVD API error for %s: %s", package_name, e)
            return _empty

        if not parsed:
            return _empty

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

    def get_download_count(self, package_name: str, ecosystem: str) -> dict | None:
        """Fetch weekly download statistics from the appropriate package registry.

        The registry is resolved from config via ecosystem/language name.
        Returns a dict with keys: weekly_downloads (int), period (str),
        registry (str).  Returns None on unknown ecosystem or fetch failure.
        All periods are normalised to a weekly equivalent where possible.
        """
        registry = self._resolve_registry(ecosystem)
        if registry is None:
            return None

        timeout = self.config['registries'][registry].get('timeout', 10)
        try:
            if registry == 'npm':
                return self._fetch_npm(package_name, timeout)
            if registry == 'pypi':
                return self._fetch_pypi(package_name, timeout)
            if registry == 'rubygems':
                return self._fetch_rubygems(package_name, timeout)
            if registry == 'crates':
                return self._fetch_crates(package_name, timeout)
            if registry == 'nuget':
                return self._fetch_nuget(package_name, timeout)
            if registry == 'packagist':
                return self._fetch_packagist(package_name, timeout)
            logger.info("No download fetcher implemented for registry %r", registry)
            return None
        except requests.RequestException as e:
            logger.error("Download count error [%s/%s]: %s", registry, package_name, e)
            return None

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
        """Fetch OpenSSF Scorecard security score (0-10) for a GitHub repo.

        Returns a dict with 'score' (float 0-10), 'date', and 'checks' (name→score map),
        or None if the repo is not indexed or the request fails.
        """
        try:
            owner, repo = self._parse_github_owner_repo(repo_url)
        except ValueError as exc:
            logger.error("Invalid repo URL for scorecard lookup: %s", exc)
            return None

        try:
            url = f"https://api.securityscorecards.dev/projects/github.com/{owner}/{repo}"
            response = requests.get(
                url,
                timeout=self.config.get('scorecard', {}).get('timeout', 10)
            )
            if response.status_code == 200:
                data = response.json()
                return {
                    'score': float(data.get('score', 0)),
                    'date': data.get('date', ''),
                    'checks': {
                        c['name']: c.get('score', -1)
                        for c in data.get('checks', [])
                    }
                }
            if response.status_code == 404:
                logger.info("Scorecard not available for %s/%s (not indexed)", owner, repo)
            else:
                logger.warning("Scorecard API returned %s for %s/%s", response.status_code, owner, repo)
            return None
        except requests.RequestException as e:
            logger.error("Scorecard API error for %s: %s", repo_url, e)
            return None

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
                if dl_data:
                    results['download_data'] = dl_data
            else:
                logger.info(
                    "No 'ecosystem' or 'language' in component_data — "
                    "download count skipped for %s", component_data['package_name']
                )

            cve_data = self.scorer.check_cves(component_data['package_name'])
            results['cve_data'] = cve_data

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

        results.update({
            'scores': scores,
            'weighted_scores': weighted_scores,
            'total_score': total_score,
            'approval': approval,
            'risk_level': self._get_risk_level(total_score)
        })

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
            days_stale = (datetime.utcnow() - last_commit).days
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
        cve_score = 100.0
        for cve in results.get('cve_data', {}).get('cves', []):
            epss = cve.get('epss', 0.0)
            severity = cve.get('severity', 'UNKNOWN')
            if epss >= _EPSS_HIGH_THRESHOLD:
                cve_score -= _DEDUCT_EPSS_HIGH
            elif epss >= _EPSS_MED_THRESHOLD:
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

        if 'scorecard_data' in results:
            scorecard_score = min(100.0, results['scorecard_data']['score'] * 10)
            return round(0.6 * cve_score + 0.4 * scorecard_score, 1)

        return round(cve_score, 1)

    def _calculate_trust_score(self, results: dict) -> float:
        """Calculate trustworthiness score (0-100).

        Blends two sub-dimensions:
        - Project maturity (60%) — based on fork count as a community proxy
        - Geopolitical risk (40%) — based on geocoded contributor locations;
          neutral (50) when location data is unavailable
        """
        # Maturity sub-score
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

        # Geo-risk sub-score
        if 'contributor_locations' in results:
            geo = self._calculate_geo_risk_score(results['contributor_locations'])
        else:
            geo = 50.0  # unknown — neutral

        return round(0.6 * maturity + 0.4 * geo, 1)

    def _calculate_geo_risk_score(self, contributors: list[dict]) -> float:
        """Score geopolitical risk from geocoded contributors (0=all high-risk, 100=all safe).

        Weights each contributor by their commit count.  Contributors whose location
        resolves to a high-risk country drive the score down sharply; unknown
        locations apply a lighter 20% penalty to account for the ambiguity.
        """
        if not contributors:
            return 50.0  # unknown — neutral

        high_risk_countries = set(
            self.config.get('risk', {}).get('high_risk_countries', [])
        )

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
        # Unknown contributors apply a light 20% penalty; confirmed high-risk is full weight
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

        has_dl   = 'download_data' in results
        has_star = 'github_metrics' in results

        if has_dl and has_star:
            dl   = _dl_score(results['download_data']['weekly_downloads'])
            star = _star_score(results['github_metrics'].get('stars', 0))
            return round(dl_w * dl + star_w * star, 1)

        if has_dl:
            return _dl_score(results['download_data']['weekly_downloads'])

        if has_star:
            return _star_score(results['github_metrics'].get('stars', 0))

        return 40.0  # no data — penalised but not zero

    def _determine_approval(self, score: float, criticality: str) -> str:
        t = self.config['scoring']['thresholds']
        if criticality == "Mission Critical":
            if score >= t['critical']:
                return "APPROVED"
            if score >= t['high']:
                return "REVIEW BOARD"
            return "PROHIBITED"
        if criticality == "Business Critical":
            if score >= t['high']:
                return "APPROVED"
            if score >= t['medium']:
                return "MITIGATION REQUIRED"
            return "PROHIBITED"
        # Non-Critical
        if score >= t['medium']:
            return "AUTO-APPROVED"
        if score >= t['low']:
            return "APPROVED"
        return "MITIGATION REQUIRED"

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
