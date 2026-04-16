"""
Unit tests for oss_scorer.py

Run with: pytest tests/test_oss_scorer.py -v
"""
import os
import sys
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta, timezone

# Ensure project root is on the path so we can import oss_scorer
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# ---------------------------------------------------------------------------
# Fixtures & helpers
# ---------------------------------------------------------------------------

MINIMAL_CONFIG = {
    'nvd': {'api_key': '', 'rate_limit': 100},  # high rate limit so tests don't sleep
    'github': {'token': '', 'timeout': 5},
    'scoring': {
        'weights': {'activity': 30, 'trust': 20, 'security': 35, 'community': 15},
        'thresholds': {'critical': 90, 'high': 80, 'medium': 70, 'low': 60},
    },
    'risk': {
        'high_risk_countries': ['CN', 'RU'],
        'critical_apps': ['payment', 'auth'],
        'maintainer_risk_multipliers': {
            'corporate': 1.0,
            'verified_individual': 1.2,
            'anonymous': 1.5,
        },
    },
}


def _make_scorer(config=None):
    """Build an OSSScorer instance that bypasses config file loading."""
    from oss_scorer import OSSScorer
    scorer = OSSScorer.__new__(OSSScorer)
    scorer.config = config or MINIMAL_CONFIG
    scorer._last_request_time = 0.0
    return scorer


def _make_workflow(config=None):
    """Build an OSSWorkflow instance with a pre-built scorer."""
    from oss_scorer import OSSWorkflow
    scorer = _make_scorer(config)
    workflow = OSSWorkflow.__new__(OSSWorkflow)
    workflow.scorer = scorer
    workflow.config = scorer.config
    return workflow


@pytest.fixture(autouse=True)
def reset_singleton():
    """Reset OSSConfig singleton between tests."""
    from oss_scorer import OSSConfig
    OSSConfig._instance = None
    yield
    OSSConfig._instance = None


# ---------------------------------------------------------------------------
# OSSConfig tests
# ---------------------------------------------------------------------------

class TestOSSConfig:
    def test_defaults_applied_on_empty_yaml(self, tmp_path, monkeypatch):
        """OSSConfig should apply sensible defaults when config is minimal."""
        cfg_file = tmp_path / 'config.yaml'
        cfg_file.write_text("scoring:\n  weights: {}\n")
        monkeypatch.chdir(tmp_path)

        from oss_scorer import OSSConfig
        config = OSSConfig()
        assert config.config['nvd']['rate_limit'] == 5
        assert config.config['github']['timeout'] == 10
        assert config.config['scoring']['weights']['activity'] == 30

    def test_env_var_overrides_github_token(self, tmp_path, monkeypatch):
        """GITHUB_TOKEN env var should override the value from config.yaml."""
        cfg_file = tmp_path / 'config.yaml'
        cfg_file.write_text("github:\n  token: 'yaml-token'\n")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv('GITHUB_TOKEN', 'env-token')

        from oss_scorer import OSSConfig
        config = OSSConfig()
        assert config.config['github']['token'] == 'env-token'

    def test_env_var_overrides_nvd_key(self, tmp_path, monkeypatch):
        """NVD_API_KEY env var should override the value from config.yaml."""
        cfg_file = tmp_path / 'config.yaml'
        cfg_file.write_text("nvd:\n  api_key: 'yaml-key'\n")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv('NVD_API_KEY', 'env-key')

        from oss_scorer import OSSConfig
        config = OSSConfig()
        assert config.config['nvd']['api_key'] == 'env-key'

    def test_missing_config_raises(self, tmp_path, monkeypatch):
        """Missing config.yaml should raise RuntimeError."""
        monkeypatch.chdir(tmp_path)

        from oss_scorer import OSSConfig
        with pytest.raises(RuntimeError, match="config loading failed"):
            OSSConfig()


# ---------------------------------------------------------------------------
# OSSScorer._parse_github_owner_repo tests
# ---------------------------------------------------------------------------

class TestParseGitHubOwnerRepo:
    def test_standard_url(self):
        scorer = _make_scorer()
        owner, repo = scorer._parse_github_owner_repo("https://github.com/expressjs/express")
        assert owner == "expressjs"
        assert repo == "express"

    def test_trailing_slash(self):
        scorer = _make_scorer()
        owner, repo = scorer._parse_github_owner_repo("https://github.com/owner/repo/")
        assert owner == "owner"
        assert repo == "repo"

    def test_dot_git_suffix_stripped(self):
        scorer = _make_scorer()
        owner, repo = scorer._parse_github_owner_repo("https://github.com/owner/repo.git")
        assert repo == "repo"

    def test_non_github_url_raises(self):
        scorer = _make_scorer()
        with pytest.raises(ValueError, match="Not a GitHub URL"):
            scorer._parse_github_owner_repo("https://gitlab.com/owner/repo")

    def test_short_path_raises(self):
        scorer = _make_scorer()
        with pytest.raises(ValueError, match="Cannot extract owner/repo"):
            scorer._parse_github_owner_repo("https://github.com/onlyowner")

    def test_empty_string_raises(self):
        scorer = _make_scorer()
        with pytest.raises(ValueError):
            scorer._parse_github_owner_repo("")


# ---------------------------------------------------------------------------
# OSSScorer._build_headers tests
# ---------------------------------------------------------------------------

class TestBuildHeaders:
    def test_github_headers_with_token(self):
        cfg = {**MINIMAL_CONFIG, 'github': {'token': 'abc123', 'timeout': 5}}
        scorer = _make_scorer(cfg)
        headers = scorer._build_headers('github')
        assert headers == {'Authorization': 'token abc123'}

    def test_github_headers_without_token(self):
        scorer = _make_scorer()
        assert scorer._build_headers('github') == {}

    def test_nvd_headers_with_key(self):
        cfg = {**MINIMAL_CONFIG, 'nvd': {'api_key': 'mykey', 'rate_limit': 100}}
        scorer = _make_scorer(cfg)
        headers = scorer._build_headers('nvd')
        assert headers == {'apiKey': 'mykey'}

    def test_nvd_headers_without_key(self):
        scorer = _make_scorer()
        assert scorer._build_headers('nvd') == {}


# ---------------------------------------------------------------------------
# OSSScorer.get_github_metrics tests
# ---------------------------------------------------------------------------

class TestGetGitHubMetrics:
    @patch('oss_scorer.requests.get')
    def test_success_maps_fields(self, mock_get):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'stargazers_count': 5000,
            'forks_count': 300,
            'pushed_at': '2024-01-01T00:00:00Z',
            'open_issues_count': 42,
            'contributors_url': 'https://api.github.com/repos/x/y/contributors'
        }
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        scorer = _make_scorer()
        result = scorer.get_github_metrics("https://github.com/expressjs/express")

        assert result['stars'] == 5000
        assert result['forks'] == 300
        assert result['open_issues'] == 42

    @patch('oss_scorer.requests.get')
    def test_network_error_returns_none(self, mock_get):
        mock_get.side_effect = requests_exception()

        scorer = _make_scorer()
        result = scorer.get_github_metrics("https://github.com/owner/repo")
        assert result is None

    def test_invalid_url_returns_none(self):
        scorer = _make_scorer()
        result = scorer.get_github_metrics("not-a-url")
        assert result is None

    def test_non_github_url_returns_none(self):
        scorer = _make_scorer()
        result = scorer.get_github_metrics("https://gitlab.com/owner/repo")
        assert result is None


def requests_exception():
    """Helper: returns a requests.RequestException for mocking."""
    import requests as req
    return req.RequestException("connection error")


# ---------------------------------------------------------------------------
# OSSScorer.check_cves tests
# ---------------------------------------------------------------------------

class TestCheckCves:
    @patch('oss_scorer.requests.get')
    def test_success_counts_critical(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'result': {
                'CVE_Items': [
                    {'impact': {'baseMetricV2': {'severity': 'HIGH'}}},
                    {'impact': {'baseMetricV2': {'severity': 'HIGH'}}},
                    {'impact': {'baseMetricV2': {'severity': 'LOW'}}},
                ]
            }
        }
        mock_get.return_value = mock_response

        scorer = _make_scorer()
        result = scorer.check_cves("requests")

        assert result['total'] == 3
        assert result['critical'] == 2

    @patch('oss_scorer.requests.get')
    def test_network_error_returns_zero_defaults(self, mock_get):
        mock_get.side_effect = requests_exception()

        scorer = _make_scorer()
        result = scorer.check_cves("some-package")

        assert result == {'total': 0, 'critical': 0, 'last_updated': result['last_updated']}
        assert result['total'] == 0

    @patch('oss_scorer.requests.get')
    def test_non_200_returns_zero_defaults(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_get.return_value = mock_response

        scorer = _make_scorer()
        result = scorer.check_cves("some-package")
        assert result['total'] == 0


# ---------------------------------------------------------------------------
# OSSWorkflow._calculate_security_score tests
# ---------------------------------------------------------------------------

class TestCalculateSecurityScore:
    def test_no_cves_is_perfect(self):
        workflow = _make_workflow()
        score = workflow._calculate_security_score({'cve_data': {'critical': 0}})
        assert score == 100

    def test_each_critical_deducts_5(self):
        workflow = _make_workflow()
        score = workflow._calculate_security_score({'cve_data': {'critical': 4}})
        assert score == 80

    def test_does_not_go_below_zero(self):
        workflow = _make_workflow()
        score = workflow._calculate_security_score({'cve_data': {'critical': 999}})
        assert score == 0

    def test_no_cve_data_returns_100(self):
        workflow = _make_workflow()
        score = workflow._calculate_security_score({})
        assert score == 100


# ---------------------------------------------------------------------------
# OSSWorkflow._calculate_activity_score tests
# ---------------------------------------------------------------------------

class TestCalculateActivityScore:
    def _results_with_commit(self, days_ago: int) -> dict:
        dt = (datetime.utcnow() - timedelta(days=days_ago)).strftime('%Y-%m-%dT%H:%M:%SZ')
        return {'github_metrics': {'last_commit': dt}}

    def test_recent_commit_scores_100(self):
        workflow = _make_workflow()
        assert workflow._calculate_activity_score(self._results_with_commit(1)) == 100

    def test_week_old_scores_80(self):
        workflow = _make_workflow()
        assert workflow._calculate_activity_score(self._results_with_commit(15)) == 80

    def test_3_month_old_scores_60(self):
        workflow = _make_workflow()
        assert workflow._calculate_activity_score(self._results_with_commit(60)) == 60

    def test_6_month_old_scores_30(self):
        workflow = _make_workflow()
        assert workflow._calculate_activity_score(self._results_with_commit(200)) == 30

    def test_over_year_scores_10(self):
        workflow = _make_workflow()
        assert workflow._calculate_activity_score(self._results_with_commit(400)) == 10

    def test_no_github_metrics_returns_40(self):
        workflow = _make_workflow()
        assert workflow._calculate_activity_score({}) == 40

    def test_missing_last_commit_returns_40(self):
        workflow = _make_workflow()
        assert workflow._calculate_activity_score({'github_metrics': {'last_commit': ''}}) == 40


# ---------------------------------------------------------------------------
# OSSWorkflow._calculate_trust_score tests
# ---------------------------------------------------------------------------

class TestCalculateTrustScore:
    def test_high_forks_scores_100(self):
        workflow = _make_workflow()
        result = {'github_metrics': {'forks': 10000}}
        assert workflow._calculate_trust_score(result) == 100

    def test_medium_forks_scores_80(self):
        workflow = _make_workflow()
        result = {'github_metrics': {'forks': 2000}}
        assert workflow._calculate_trust_score(result) == 80

    def test_low_forks_scores_60(self):
        workflow = _make_workflow()
        result = {'github_metrics': {'forks': 500}}
        assert workflow._calculate_trust_score(result) == 60

    def test_very_low_forks_scores_40(self):
        workflow = _make_workflow()
        result = {'github_metrics': {'forks': 10}}
        assert workflow._calculate_trust_score(result) == 40

    def test_no_github_metrics_returns_50(self):
        workflow = _make_workflow()
        assert workflow._calculate_trust_score({}) == 50


# ---------------------------------------------------------------------------
# OSSWorkflow._calculate_community_score tests
# ---------------------------------------------------------------------------

class TestCalculateCommunityScore:
    def test_high_stars_scores_100(self):
        workflow = _make_workflow()
        assert workflow._calculate_community_score({'github_metrics': {'stars': 50000}}) == 100

    def test_medium_stars_scores_80(self):
        workflow = _make_workflow()
        assert workflow._calculate_community_score({'github_metrics': {'stars': 5000}}) == 80

    def test_low_stars_scores_60(self):
        workflow = _make_workflow()
        assert workflow._calculate_community_score({'github_metrics': {'stars': 500}}) == 60

    def test_very_low_stars_scores_40(self):
        workflow = _make_workflow()
        assert workflow._calculate_community_score({'github_metrics': {'stars': 5}}) == 40

    def test_no_github_metrics_returns_40(self):
        workflow = _make_workflow()
        assert workflow._calculate_community_score({}) == 40


# ---------------------------------------------------------------------------
# OSSWorkflow._determine_approval tests
# ---------------------------------------------------------------------------

class TestDetermineApproval:
    def test_mission_critical_approved(self):
        wf = _make_workflow()
        assert wf._determine_approval(95, "Mission Critical") == "APPROVED"

    def test_mission_critical_review_board(self):
        wf = _make_workflow()
        assert wf._determine_approval(85, "Mission Critical") == "REVIEW BOARD"

    def test_mission_critical_prohibited(self):
        wf = _make_workflow()
        assert wf._determine_approval(50, "Mission Critical") == "PROHIBITED"

    def test_business_critical_approved(self):
        wf = _make_workflow()
        assert wf._determine_approval(85, "Business Critical") == "APPROVED"

    def test_business_critical_mitigation_required(self):
        wf = _make_workflow()
        assert wf._determine_approval(75, "Business Critical") == "MITIGATION REQUIRED"

    def test_business_critical_prohibited(self):
        wf = _make_workflow()
        assert wf._determine_approval(50, "Business Critical") == "PROHIBITED"

    def test_non_critical_auto_approved(self):
        wf = _make_workflow()
        assert wf._determine_approval(75, "Non-Critical") == "AUTO-APPROVED"

    def test_non_critical_approved(self):
        wf = _make_workflow()
        assert wf._determine_approval(65, "Non-Critical") == "APPROVED"

    def test_non_critical_mitigation_required(self):
        wf = _make_workflow()
        assert wf._determine_approval(50, "Non-Critical") == "MITIGATION REQUIRED"

    def test_exact_threshold_boundaries(self):
        """Boundary values for each threshold."""
        wf = _make_workflow()
        # critical=90
        assert wf._determine_approval(90, "Mission Critical") == "APPROVED"
        assert wf._determine_approval(89.9, "Mission Critical") == "REVIEW BOARD"
        # high=80
        assert wf._determine_approval(80, "Mission Critical") == "REVIEW BOARD"
        assert wf._determine_approval(79.9, "Mission Critical") == "PROHIBITED"


# ---------------------------------------------------------------------------
# OSSWorkflow._get_risk_level tests
# ---------------------------------------------------------------------------

class TestGetRiskLevel:
    def test_score_above_critical(self):
        assert _make_workflow()._get_risk_level(95) == "Low"

    def test_score_above_high(self):
        assert _make_workflow()._get_risk_level(85) == "Medium-Low"

    def test_score_above_medium(self):
        assert _make_workflow()._get_risk_level(75) == "Medium"

    def test_score_above_low(self):
        assert _make_workflow()._get_risk_level(65) == "Medium-High"

    def test_score_below_low(self):
        assert _make_workflow()._get_risk_level(50) == "High"


# ---------------------------------------------------------------------------
# OSSWorkflow.evaluate_component input validation tests
# ---------------------------------------------------------------------------

class TestEvaluateComponentValidation:
    def test_non_dict_raises_type_error(self):
        wf = _make_workflow()
        with pytest.raises(TypeError, match="component_data must be a dict"):
            wf.evaluate_component("not a dict")

    def test_invalid_criticality_raises_value_error(self):
        wf = _make_workflow()
        with pytest.raises(ValueError, match="Invalid criticality"):
            wf.evaluate_component({'criticality': 'Unknown Level'})

    @patch('oss_scorer.requests.get')
    def test_valid_non_critical_returns_result(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'result': {'CVE_Items': []}}
        mock_get.return_value = mock_response

        wf = _make_workflow()
        result = wf.evaluate_component({
            'package_name': 'requests',
            'criticality': 'Non-Critical'
        })
        assert 'total_score' in result
        assert 'approval' in result
        assert 'risk_level' in result
