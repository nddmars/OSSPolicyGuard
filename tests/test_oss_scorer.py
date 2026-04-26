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

_REGISTRY_CFG = {
    'npm':       {'enabled': True, 'timeout': 5, 'languages': ['javascript', 'typescript', 'nodejs', 'node']},
    'pypi':      {'enabled': True, 'timeout': 5, 'languages': ['python']},
    'rubygems':  {'enabled': True, 'timeout': 5, 'languages': ['ruby']},
    'crates':    {'enabled': True, 'timeout': 5, 'languages': ['rust']},
    'nuget':     {'enabled': True, 'timeout': 5, 'languages': ['csharp', 'c#', 'dotnet']},
    'packagist': {'enabled': True, 'timeout': 5, 'languages': ['php']},
    'maven':     {'enabled': False, 'timeout': 5, 'languages': ['java', 'kotlin']},
}

MINIMAL_CONFIG = {
    'nvd': {'api_key': '', 'rate_limit': 100},  # high rate limit so tests don't sleep
    'github': {'token': '', 'timeout': 5},
    'scoring': {
        'weights': {'activity': 30, 'trust': 20, 'security': 35, 'community': 15},
        'thresholds': {'critical': 90, 'high': 80, 'medium': 70, 'low': 60},
        'community': {
            'weekly_high': 1_000_000,
            'weekly_med': 100_000,
            'weekly_low': 10_000,
            'download_weight': 0.7,
            'star_weight': 0.3,
        },
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
    'registries': _REGISTRY_CFG,
    'geocoding': {
        'enabled': True, 'max_contributors': 10,
        'nominatim_url': 'https://nominatim.openstreetmap.org',
        'user_agent': 'test/1.0',
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
# OSSScorer.check_cves tests  (NVD v2 format)
# ---------------------------------------------------------------------------

def _nvd_v2_response(*cves):
    """Build a minimal NVD v2 API response from (id, severity, base_score) tuples."""
    vulns = []
    for cve_id, severity, base_score in cves:
        vulns.append({
            'cve': {
                'id': cve_id,
                'metrics': {
                    'cvssMetricV31': [{
                        'cvssData': {
                            'baseSeverity': severity,
                            'baseScore': base_score,
                        }
                    }]
                }
            }
        })
    return {'vulnerabilities': vulns}


def _epss_response(*pairs):
    """Build a FIRST EPSS API response from (cve_id, epss_score) tuples."""
    return {
        'data': [
            {'cve': cve_id, 'epss': str(epss), 'percentile': '0.9'}
            for cve_id, epss in pairs
        ]
    }


class TestCheckCves:
    @patch('oss_scorer.requests.get')
    def test_success_parses_nvd_v2_severity_bands(self, mock_get):
        # First call: NVD rate-limiter probe (ignored), second: real NVD v2, third: EPSS
        nvd_resp = MagicMock(status_code=200)
        nvd_resp.json.return_value = _nvd_v2_response(
            ('CVE-2021-0001', 'CRITICAL', 9.8),
            ('CVE-2021-0002', 'HIGH', 7.5),
            ('CVE-2021-0003', 'MEDIUM', 5.0),
        )
        epss_resp = MagicMock(status_code=200)
        epss_resp.json.return_value = _epss_response()  # no EPSS data

        mock_get.side_effect = [nvd_resp, nvd_resp, epss_resp]

        scorer = _make_scorer()
        result = scorer.check_cves("some-lib")

        assert result['total'] == 3
        assert result['critical'] == 1
        assert result['high'] == 1
        assert result['medium'] == 1

    @patch('oss_scorer.requests.get')
    def test_epss_scores_attached_to_cves(self, mock_get):
        nvd_resp = MagicMock(status_code=200)
        nvd_resp.json.return_value = _nvd_v2_response(
            ('CVE-2021-44228', 'CRITICAL', 10.0),
        )
        epss_resp = MagicMock(status_code=200)
        epss_resp.json.return_value = _epss_response(('CVE-2021-44228', 0.975))

        mock_get.side_effect = [nvd_resp, nvd_resp, epss_resp]

        scorer = _make_scorer()
        result = scorer.check_cves("log4j")

        assert result['max_epss'] == 0.975
        assert result['epss_high'] == 1
        assert result['cves'][0]['epss'] == 0.975

    @patch('oss_scorer.requests.get')
    def test_network_error_returns_empty_structure(self, mock_get):
        mock_get.side_effect = requests_exception()

        scorer = _make_scorer()
        result = scorer.check_cves("some-package")

        assert result['total'] == 0
        assert result['cves'] == []
        assert 'last_updated' in result

    @patch('oss_scorer.requests.get')
    def test_non_200_returns_empty_structure(self, mock_get):
        bad_resp = MagicMock(status_code=403)
        mock_get.return_value = bad_resp

        scorer = _make_scorer()
        result = scorer.check_cves("some-package")
        assert result['total'] == 0


# ---------------------------------------------------------------------------
# OSSScorer.get_epss_scores tests
# ---------------------------------------------------------------------------

class TestGetEpssScores:
    @patch('oss_scorer.requests.get')
    def test_returns_epss_and_percentile(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = _epss_response(
            ('CVE-2021-44228', 0.975),
            ('CVE-2021-45046', 0.312),
        )
        scorer = _make_scorer()
        result = scorer.get_epss_scores(['CVE-2021-44228', 'CVE-2021-45046'])

        assert result['CVE-2021-44228']['epss'] == 0.975
        assert result['CVE-2021-45046']['epss'] == 0.312

    @patch('oss_scorer.requests.get')
    def test_network_error_returns_empty(self, mock_get):
        mock_get.side_effect = requests_exception()
        scorer = _make_scorer()
        assert scorer.get_epss_scores(['CVE-2021-44228']) == {}

    def test_empty_list_returns_empty(self):
        scorer = _make_scorer()
        assert scorer.get_epss_scores([]) == {}

    @patch('oss_scorer.requests.get')
    def test_batches_over_30_cves(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {'data': []}

        scorer = _make_scorer()
        cve_ids = [f"CVE-2024-{i:04d}" for i in range(35)]
        scorer.get_epss_scores(cve_ids)

        assert mock_get.call_count == 2  # 30 + 5 → 2 batches


# ---------------------------------------------------------------------------
# OSSWorkflow._calculate_security_score tests  (EPSS-weighted)
# ---------------------------------------------------------------------------

class TestCalculateSecurityScore:
    def _cve(self, severity='UNKNOWN', epss=0.0):
        return {'severity': severity, 'epss': epss, 'base_score': 7.0, 'id': 'CVE-X'}

    def test_no_cve_data_returns_100(self):
        assert _make_workflow()._calculate_security_score({}) == 100.0

    def test_empty_cves_list_returns_100(self):
        assert _make_workflow()._calculate_security_score({'cve_data': {'cves': []}}) == 100.0

    def test_high_epss_deducts_15(self):
        # EPSS ≥ 0.5 → -15 pts
        result = _make_workflow()._calculate_security_score(
            {'cve_data': {'cves': [self._cve(epss=0.75)]}}
        )
        assert result == 85.0

    def test_medium_epss_deducts_8(self):
        # EPSS 0.1–0.5 → -8 pts
        result = _make_workflow()._calculate_security_score(
            {'cve_data': {'cves': [self._cve(epss=0.25)]}}
        )
        assert result == 92.0

    def test_low_epss_deducts_2(self):
        # EPSS > 0 but < 0.1 → -2 pts
        result = _make_workflow()._calculate_security_score(
            {'cve_data': {'cves': [self._cve(epss=0.01)]}}
        )
        assert result == 98.0

    def test_no_epss_critical_severity_deducts_10(self):
        result = _make_workflow()._calculate_security_score(
            {'cve_data': {'cves': [self._cve(severity='CRITICAL', epss=0.0)]}}
        )
        assert result == 90.0

    def test_no_epss_high_severity_deducts_5(self):
        result = _make_workflow()._calculate_security_score(
            {'cve_data': {'cves': [self._cve(severity='HIGH', epss=0.0)]}}
        )
        assert result == 95.0

    def test_no_epss_medium_severity_deducts_2(self):
        result = _make_workflow()._calculate_security_score(
            {'cve_data': {'cves': [self._cve(severity='MEDIUM', epss=0.0)]}}
        )
        assert result == 98.0

    def test_multiple_cves_accumulate_deductions(self):
        # 1 actively exploited (-15) + 2 CVSS HIGH no EPSS (-5 each) = -25 → 75
        cves = [
            self._cve(epss=0.9),
            self._cve(severity='HIGH', epss=0.0),
            self._cve(severity='HIGH', epss=0.0),
        ]
        result = _make_workflow()._calculate_security_score({'cve_data': {'cves': cves}})
        assert result == 75.0

    def test_score_does_not_go_below_zero(self):
        cves = [self._cve(epss=0.9) for _ in range(20)]
        result = _make_workflow()._calculate_security_score({'cve_data': {'cves': cves}})
        assert result == 0.0

    def test_scorecard_blended_at_40_percent(self):
        # CVE score = 85 (1 high-EPSS), Scorecard = 5.0 → 50 out of 100
        # expected = 0.6*85 + 0.4*50 = 51+20 = 71
        result = _make_workflow()._calculate_security_score({
            'cve_data': {'cves': [self._cve(epss=0.75)]},
            'scorecard_data': {'score': 5.0, 'date': '', 'checks': {}},
        })
        assert result == 71.0


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
    # Without contributor_locations the geo sub-score is neutral (50), so the
    # blended result is: 0.6 * maturity + 0.4 * 50.

    def test_high_forks_no_geo_data(self):
        # maturity=100, geo=50 → 0.6*100 + 0.4*50 = 80
        workflow = _make_workflow()
        assert workflow._calculate_trust_score({'github_metrics': {'forks': 10000}}) == 80.0

    def test_medium_forks_no_geo_data(self):
        # maturity=80, geo=50 → 0.6*80 + 0.4*50 = 68
        workflow = _make_workflow()
        assert workflow._calculate_trust_score({'github_metrics': {'forks': 2000}}) == 68.0

    def test_low_forks_no_geo_data(self):
        # maturity=60, geo=50 → 0.6*60 + 0.4*50 = 56
        workflow = _make_workflow()
        assert workflow._calculate_trust_score({'github_metrics': {'forks': 500}}) == 56.0

    def test_very_low_forks_no_geo_data(self):
        # maturity=40, geo=50 → 0.6*40 + 0.4*50 = 44
        workflow = _make_workflow()
        assert workflow._calculate_trust_score({'github_metrics': {'forks': 10}}) == 44.0

    def test_no_github_metrics_returns_50(self):
        # maturity=50 (no data), geo=50 (no data) → 50
        workflow = _make_workflow()
        assert workflow._calculate_trust_score({}) == 50.0


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
        # NVD v2 empty response (two calls: rate-limiter probe + actual)
        # followed by EPSS empty response
        nvd_resp = MagicMock(status_code=200)
        nvd_resp.json.return_value = {'vulnerabilities': []}
        epss_resp = MagicMock(status_code=200)
        epss_resp.json.return_value = {'data': []}
        mock_get.return_value = nvd_resp  # reuse for all calls

        wf = _make_workflow()
        result = wf.evaluate_component({
            'package_name': 'requests',
            'criticality': 'Non-Critical'
        })
        assert 'total_score' in result
        assert 'approval' in result
        assert 'risk_level' in result


# ---------------------------------------------------------------------------
# OSSScorer.get_scorecard tests
# ---------------------------------------------------------------------------

class TestGetScorecard:
    @patch('oss_scorer.requests.get')
    def test_success_parses_score_and_checks(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            'score': 7.5,
            'date': '2024-06-01',
            'checks': [
                {'name': 'Code-Review', 'score': 10},
                {'name': 'Branch-Protection', 'score': 5},
            ]
        }

        scorer = _make_scorer()
        result = scorer.get_scorecard("https://github.com/owner/repo")

        assert result is not None
        assert result['score'] == 7.5
        assert result['date'] == '2024-06-01'
        assert result['checks']['Code-Review'] == 10
        assert result['checks']['Branch-Protection'] == 5

    @patch('oss_scorer.requests.get')
    def test_404_returns_none(self, mock_get):
        mock_get.return_value.status_code = 404

        scorer = _make_scorer()
        assert scorer.get_scorecard("https://github.com/owner/repo") is None

    @patch('oss_scorer.requests.get')
    def test_network_error_returns_none(self, mock_get):
        mock_get.side_effect = requests_exception()

        scorer = _make_scorer()
        assert scorer.get_scorecard("https://github.com/owner/repo") is None

    def test_invalid_url_returns_none(self):
        scorer = _make_scorer()
        assert scorer.get_scorecard("not-a-url") is None


# ---------------------------------------------------------------------------
# Security score blending tests (with Scorecard)
# ---------------------------------------------------------------------------

class TestSecurityScoreBlending:
    def test_no_cves_no_scorecard_is_100(self):
        wf = _make_workflow()
        assert wf._calculate_security_score({}) == 100.0

    def test_scorecard_blended_at_40_percent(self):
        wf = _make_workflow()
        # CVE score = 100, scorecard score = 5.0 (→50 out of 100)
        # expected = 0.6*100 + 0.4*50 = 60+20 = 80
        result = wf._calculate_security_score({
            'scorecard_data': {'score': 5.0, 'date': '', 'checks': {}}
        })
        assert result == 80.0

    def test_perfect_scorecard_boosts_score(self):
        wf = _make_workflow()
        # 4 CRITICAL CVEs, no EPSS → -10 each → CVE score = 60
        # perfect scorecard (10 → 100) → 0.6*60 + 0.4*100 = 76
        cves = [{'severity': 'CRITICAL', 'epss': 0.0, 'id': f'CVE-X-{i}', 'base_score': 9.8}
                for i in range(4)]
        result = wf._calculate_security_score({
            'cve_data': {'cves': cves},
            'scorecard_data': {'score': 10.0, 'date': '', 'checks': {}}
        })
        assert result == 76.0

    def test_zero_scorecard_penalises(self):
        wf = _make_workflow()
        # No CVEs → CVE score=100; scorecard=0 → 0.6*100 + 0.4*0 = 60
        result = wf._calculate_security_score({
            'scorecard_data': {'score': 0.0, 'date': '', 'checks': {}}
        })
        assert result == 60.0


# ---------------------------------------------------------------------------
# OSSScorer._geocode_location tests
# ---------------------------------------------------------------------------

class TestGeocodeLocation:
    def test_empty_string_returns_empty(self):
        scorer = _make_scorer()
        assert scorer._geocode_location('') == ''

    def test_known_city_china(self):
        scorer = _make_scorer()
        assert scorer._geocode_location('Shanghai, China') == 'CN'

    def test_known_city_russia(self):
        scorer = _make_scorer()
        assert scorer._geocode_location('Moscow') == 'RU'

    def test_known_city_us(self):
        scorer = _make_scorer()
        assert scorer._geocode_location('San Francisco, CA') == 'US'

    def test_known_country_germany(self):
        scorer = _make_scorer()
        assert scorer._geocode_location('Berlin, Germany') == 'DE'

    def test_case_insensitive(self):
        scorer = _make_scorer()
        assert scorer._geocode_location('BEIJING') == 'CN'

    @patch('oss_scorer.requests.get')
    def test_unknown_location_calls_nominatim(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = [
            {'address': {'country_code': 'fr'}}
        ]
        cfg = {**MINIMAL_CONFIG, 'geocoding': {'enabled': True, 'nominatim_url': 'https://nominatim.openstreetmap.org', 'user_agent': 'test/1.0', 'max_contributors': 10}}
        scorer = _make_scorer(cfg)
        # "Bordeaux" is not in our fast-path map
        result = scorer._geocode_location('Bordeaux')
        assert result == 'FR'

    @patch('oss_scorer.requests.get')
    def test_nominatim_network_error_returns_empty(self, mock_get):
        mock_get.side_effect = requests_exception()
        cfg = {**MINIMAL_CONFIG, 'geocoding': {'enabled': True, 'nominatim_url': 'https://nominatim.openstreetmap.org', 'user_agent': 'test/1.0', 'max_contributors': 10}}
        scorer = _make_scorer(cfg)
        result = scorer._geocode_location('Someplace Unknown')
        assert result == ''

    def test_geocoding_disabled_skips_nominatim(self):
        cfg = {**MINIMAL_CONFIG, 'geocoding': {'enabled': False, 'max_contributors': 10}}
        scorer = _make_scorer(cfg)
        # A location not in the fast-path map should return '' without any HTTP call
        result = scorer._geocode_location('Bordeaux')
        assert result == ''


# ---------------------------------------------------------------------------
# OSSWorkflow._calculate_geo_risk_score tests
# ---------------------------------------------------------------------------

class TestCalculateGeoRiskScore:
    def _contrib(self, login, contributions, country_code):
        return {'login': login, 'contributions': contributions, 'country_code': country_code}

    def test_empty_contributors_returns_neutral(self):
        wf = _make_workflow()
        assert wf._calculate_geo_risk_score([]) == 50.0

    def test_all_safe_countries_scores_100(self):
        wf = _make_workflow()
        contributors = [
            self._contrib('alice', 100, 'US'),
            self._contrib('bob', 80, 'DE'),
        ]
        assert wf._calculate_geo_risk_score(contributors) == 100.0

    def test_all_high_risk_scores_0(self):
        wf = _make_workflow()
        contributors = [
            self._contrib('user1', 200, 'CN'),
            self._contrib('user2', 100, 'RU'),
        ]
        assert wf._calculate_geo_risk_score(contributors) == 0.0

    def test_mixed_risk_weighted_by_commits(self):
        wf = _make_workflow()
        # 25% commits from high-risk (CN), 75% from safe (US)
        contributors = [
            self._contrib('alice', 75, 'US'),
            self._contrib('bob', 25, 'CN'),
        ]
        # penalty = 0.25 → score = 100 * (1 - 0.25) = 75
        assert wf._calculate_geo_risk_score(contributors) == 75.0

    def test_unknown_location_applies_partial_penalty(self):
        wf = _make_workflow()
        # 100% unknown → penalty = 0.2*1.0 = 0.2 → score = 80
        contributors = [self._contrib('anon', 100, '')]
        assert wf._calculate_geo_risk_score(contributors) == 80.0

    def test_mixed_safe_and_unknown(self):
        wf = _make_workflow()
        # 50% US (safe), 50% unknown → penalty = 0.2*0.5 = 0.1 → score = 90
        contributors = [
            self._contrib('alice', 50, 'US'),
            self._contrib('anon', 50, ''),
        ]
        assert wf._calculate_geo_risk_score(contributors) == 90.0


# ---------------------------------------------------------------------------
# Trust score blending tests (maturity + geo-risk)
# ---------------------------------------------------------------------------

class TestTrustScoreBlending:
    def test_no_data_returns_neutral(self):
        wf = _make_workflow()
        # No github_metrics, no contributor_locations → 0.6*50 + 0.4*50 = 50
        assert wf._calculate_trust_score({}) == 50.0

    def test_high_forks_safe_contributors_scores_high(self):
        wf = _make_workflow()
        results = {
            'github_metrics': {'forks': 10000},
            'contributor_locations': [
                {'login': 'a', 'contributions': 100, 'country_code': 'US'},
            ]
        }
        # maturity=100, geo=100 → 0.6*100 + 0.4*100 = 100
        assert wf._calculate_trust_score(results) == 100.0

    def test_high_forks_high_risk_contributors_penalised(self):
        wf = _make_workflow()
        results = {
            'github_metrics': {'forks': 10000},
            'contributor_locations': [
                {'login': 'a', 'contributions': 100, 'country_code': 'CN'},
            ]
        }
        # maturity=100, geo=0 → 0.6*100 + 0.4*0 = 60
        assert wf._calculate_trust_score(results) == 60.0

    def test_no_contributors_uses_neutral_geo(self):
        wf = _make_workflow()
        results = {'github_metrics': {'forks': 6000}}
        # maturity=100 (>5000), geo=50 (neutral) → 0.6*100 + 0.4*50 = 80
        assert wf._calculate_trust_score(results) == 80.0


# ---------------------------------------------------------------------------
# get_contributor_locations tests
# ---------------------------------------------------------------------------

class TestGetContributorLocations:
    @patch('oss_scorer.requests.get')
    def test_returns_geocoded_contributors(self, mock_get):
        contributors_resp = MagicMock()
        contributors_resp.status_code = 200
        contributors_resp.raise_for_status = MagicMock()
        contributors_resp.json.return_value = [
            {'login': 'alice', 'contributions': 100},
            {'login': 'bob', 'contributions': 50},
        ]

        alice_resp = MagicMock()
        alice_resp.status_code = 200
        alice_resp.raise_for_status = MagicMock()
        alice_resp.json.return_value = {'location': 'San Francisco, CA', 'company': 'Acme'}

        bob_resp = MagicMock()
        bob_resp.status_code = 200
        bob_resp.raise_for_status = MagicMock()
        bob_resp.json.return_value = {'location': 'Beijing, China', 'company': ''}

        mock_get.side_effect = [contributors_resp, alice_resp, bob_resp]

        cfg = {**MINIMAL_CONFIG, 'geocoding': {'enabled': True, 'max_contributors': 10, 'nominatim_url': 'https://nominatim.openstreetmap.org', 'user_agent': 'test/1.0'}}
        scorer = _make_scorer(cfg)
        results = scorer.get_contributor_locations('https://api.github.com/repos/x/y/contributors')

        assert len(results) == 2
        assert results[0]['login'] == 'alice'
        assert results[0]['country_code'] == 'US'
        assert results[1]['login'] == 'bob'
        assert results[1]['country_code'] == 'CN'

    @patch('oss_scorer.requests.get')
    def test_network_error_returns_empty_list(self, mock_get):
        mock_get.side_effect = requests_exception()
        scorer = _make_scorer()
        result = scorer.get_contributor_locations('https://api.github.com/repos/x/y/contributors')
        assert result == []

    def test_geocoding_disabled_returns_empty_list(self):
        cfg = {**MINIMAL_CONFIG, 'geocoding': {'enabled': False, 'max_contributors': 10}}
        scorer = _make_scorer(cfg)
        result = scorer.get_contributor_locations('https://api.github.com/repos/x/y/contributors')
        assert result == []


# ---------------------------------------------------------------------------
# OSSScorer._resolve_registry tests
# ---------------------------------------------------------------------------

class TestResolveRegistry:
    def test_direct_registry_name_npm(self):
        assert _make_scorer()._resolve_registry('npm') == 'npm'

    def test_direct_registry_name_pypi(self):
        assert _make_scorer()._resolve_registry('pypi') == 'pypi'

    def test_language_alias_python_resolves_pypi(self):
        assert _make_scorer()._resolve_registry('python') == 'pypi'

    def test_language_alias_javascript_resolves_npm(self):
        assert _make_scorer()._resolve_registry('javascript') == 'npm'

    def test_language_alias_typescript_resolves_npm(self):
        assert _make_scorer()._resolve_registry('typescript') == 'npm'

    def test_language_alias_rust_resolves_crates(self):
        assert _make_scorer()._resolve_registry('rust') == 'crates'

    def test_language_alias_csharp_resolves_nuget(self):
        assert _make_scorer()._resolve_registry('csharp') == 'nuget'

    def test_language_alias_php_resolves_packagist(self):
        assert _make_scorer()._resolve_registry('php') == 'packagist'

    def test_case_insensitive(self):
        assert _make_scorer()._resolve_registry('PYTHON') == 'pypi'
        assert _make_scorer()._resolve_registry('JavaScript') == 'npm'

    def test_unknown_ecosystem_returns_none(self):
        assert _make_scorer()._resolve_registry('cobol') is None

    def test_disabled_registry_returns_none(self):
        # maven is disabled in MINIMAL_CONFIG
        assert _make_scorer()._resolve_registry('java') is None
        assert _make_scorer()._resolve_registry('maven') is None


# ---------------------------------------------------------------------------
# OSSScorer.get_download_count — per-registry fetcher tests
# ---------------------------------------------------------------------------

class TestGetDownloadCount:
    @patch('oss_scorer.requests.get')
    def test_npm_extracts_downloads(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.raise_for_status = MagicMock()
        mock_get.return_value.json.return_value = {'downloads': 5_000_000}

        result = _make_scorer().get_download_count('lodash', 'npm')

        assert result['weekly_downloads'] == 5_000_000
        assert result['period'] == 'weekly'
        assert result['registry'] == 'npm'

    @patch('oss_scorer.requests.get')
    def test_pypi_extracts_last_week(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.raise_for_status = MagicMock()
        mock_get.return_value.json.return_value = {
            'data': {'last_week': 12_000_000, 'last_month': 48_000_000}
        }

        result = _make_scorer().get_download_count('requests', 'python')

        assert result['weekly_downloads'] == 12_000_000
        assert result['registry'] == 'pypi'

    @patch('oss_scorer.requests.get')
    def test_rubygems_estimates_weekly(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.raise_for_status = MagicMock()
        mock_get.return_value.json.return_value = {'version_downloads': 520_000}

        result = _make_scorer().get_download_count('rails', 'ruby')

        # 520_000 // 52 = 10_000
        assert result['weekly_downloads'] == 10_000
        assert result['period'] == 'estimated_weekly'
        assert result['registry'] == 'rubygems'

    @patch('oss_scorer.requests.get')
    def test_crates_divides_90day_by_13(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.raise_for_status = MagicMock()
        mock_get.return_value.json.return_value = {
            'crate': {'recent_downloads': 130_000}
        }

        result = _make_scorer().get_download_count('serde', 'rust')

        assert result['weekly_downloads'] == 10_000  # 130_000 // 13
        assert result['registry'] == 'crates'

    @patch('oss_scorer.requests.get')
    def test_nuget_divides_total_by_104(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.raise_for_status = MagicMock()
        mock_get.return_value.json.return_value = {
            'data': [{'totalDownloads': 10_400_000}]
        }

        result = _make_scorer().get_download_count('Newtonsoft.Json', 'csharp')

        assert result['weekly_downloads'] == 100_000  # 10_400_000 // 104
        assert result['registry'] == 'nuget'

    @patch('oss_scorer.requests.get')
    def test_packagist_divides_monthly_by_4(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.raise_for_status = MagicMock()
        mock_get.return_value.json.return_value = {
            'package': {'downloads': {'monthly': 400_000}}
        }

        result = _make_scorer().get_download_count('laravel/framework', 'php')

        assert result['weekly_downloads'] == 100_000  # 400_000 // 4
        assert result['registry'] == 'packagist'

    def test_packagist_without_vendor_slash_returns_zero(self):
        result = _make_scorer().get_download_count('laravel', 'php')
        assert result['weekly_downloads'] == 0

    def test_unknown_ecosystem_returns_none(self):
        result = _make_scorer().get_download_count('mylib', 'cobol')
        assert result is None

    def test_disabled_registry_returns_none(self):
        result = _make_scorer().get_download_count('mylib', 'java')
        assert result is None

    @patch('oss_scorer.requests.get')
    def test_network_error_returns_none(self, mock_get):
        mock_get.side_effect = requests_exception()
        result = _make_scorer().get_download_count('requests', 'python')
        assert result is None


# ---------------------------------------------------------------------------
# OSSWorkflow._calculate_community_score — with download data
# ---------------------------------------------------------------------------

class TestCalculateCommunityScoreWithDownloads:
    def _results(self, weekly=None, stars=None):
        r = {}
        if weekly is not None:
            r['download_data'] = {'weekly_downloads': weekly, 'period': 'weekly', 'registry': 'npm'}
        if stars is not None:
            r['github_metrics'] = {'stars': stars}
        return r

    def test_high_downloads_and_high_stars_scores_100(self):
        # dl=100, star=100 → 0.7*100 + 0.3*100 = 100
        wf = _make_workflow()
        assert wf._calculate_community_score(self._results(2_000_000, 20_000)) == 100.0

    def test_downloads_dominate_over_low_stars(self):
        # dl=100 (>1M), star=40 (<100 stars) → 0.7*100 + 0.3*40 = 70+12 = 82
        wf = _make_workflow()
        assert wf._calculate_community_score(self._results(2_000_000, 50)) == 82.0

    def test_medium_downloads_medium_stars(self):
        # dl=80 (>100K), star=80 (>1K) → 0.7*80 + 0.3*80 = 80
        wf = _make_workflow()
        assert wf._calculate_community_score(self._results(500_000, 5_000)) == 80.0

    def test_downloads_only_no_stars(self):
        # only download data — returns download score directly
        wf = _make_workflow()
        assert wf._calculate_community_score(self._results(weekly=200_000)) == 80.0

    def test_stars_only_no_downloads(self):
        # only star data — returns star score directly (unchanged behaviour)
        wf = _make_workflow()
        assert wf._calculate_community_score(self._results(stars=15_000)) == 100.0

    def test_no_data_returns_40(self):
        wf = _make_workflow()
        assert wf._calculate_community_score({}) == 40.0

    def test_low_downloads_below_threshold_scores_40(self):
        wf = _make_workflow()
        assert wf._calculate_community_score(self._results(weekly=500)) == 40.0
