import os
import time
import logging
import yaml
import pandas as pd
import requests
from datetime import datetime, timezone
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
_CVE_CRITICAL_DEDUCTION = 5
_STARS_HIGH_THRESHOLD = 10_000
_STARS_MED_THRESHOLD = 1_000
_STARS_LOW_THRESHOLD = 100
_FORKS_HIGH_THRESHOLD = 5_000
_FORKS_MED_THRESHOLD = 1_000
_FORKS_LOW_THRESHOLD = 100

_VALID_CRITICALITY = {"Mission Critical", "Business Critical", "Non-Critical"}


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
        """Check NVD database for CVEs"""
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={package_name}"
            headers = self._build_headers('nvd')

            response = self._rate_limited_get(
                url,
                headers=headers,
                timeout=self.config['github']['timeout']
            )

            if response.status_code == 200:
                cves = response.json().get("result", {}).get("CVE_Items", [])
                return {
                    'total': len(cves),
                    'critical': sum(1 for cve in cves if
                                    cve.get('impact', {}).get('baseMetricV2', {}).get('severity') == 'HIGH'),
                    'last_updated': datetime.now().isoformat()
                }
            logger.warning("NVD API returned status %s for package %s", response.status_code, package_name)
            return {'total': 0, 'critical': 0, 'last_updated': datetime.now().isoformat()}
        except requests.RequestException as e:
            logger.error("NVD API error for %s: %s", package_name, e)
            return {'total': 0, 'critical': 0, 'last_updated': datetime.now().isoformat()}


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
                results.update({'github_metrics': gh_metrics})

        # CVE check
        if 'package_name' in component_data:
            cve_data = self.scorer.check_cves(component_data['package_name'])
            results.update({'cve_data': cve_data})

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
        """Calculate security score (0-100) based on CVEs and practices"""
        base_score = 100
        if 'cve_data' in results:
            base_score -= results['cve_data']['critical'] * _CVE_CRITICAL_DEDUCTION
        return max(0, min(100, base_score))

    def _calculate_trust_score(self, results: dict) -> float:
        """Calculate trustworthiness score (0-100) based on fork count as a community proxy."""
        if 'github_metrics' not in results:
            return 50  # unknown - neutral fallback
        forks = results['github_metrics'].get('forks', 0)
        if forks > _FORKS_HIGH_THRESHOLD:
            return 100
        if forks > _FORKS_MED_THRESHOLD:
            return 80
        if forks > _FORKS_LOW_THRESHOLD:
            return 60
        return 40

    def _calculate_community_score(self, results: dict) -> float:
        """Calculate community/adoption score (0-100) based on star count."""
        if 'github_metrics' in results:
            stars = results['github_metrics'].get('stars', 0)
            if stars > _STARS_HIGH_THRESHOLD:
                return 100
            if stars > _STARS_MED_THRESHOLD:
                return 80
            if stars > _STARS_LOW_THRESHOLD:
                return 60
        return 40

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
