import os
import sys
import pytest
import requests
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from oss_scorer import GitHubProvider, ScorecardProvider, ProviderStatus


def test_github_provider_success(monkeypatch):
    mock_get = MagicMock()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = {
        'stargazers_count': 1200,
        'forks_count': 45,
        'pushed_at': '2025-01-01T00:00:00Z',
        'open_issues_count': 7,
        'contributors_url': 'https://api.github.com/repos/x/y/contributors',
    }
    mock_get.return_value = mock_response
    monkeypatch.setattr('oss_scorer.requests.get', mock_get)

    provider = GitHubProvider({'github': {'timeout': 5, 'rate_limit': 100, 'token': ''}})
    response = provider.fetch('https://github.com/expressjs/express')

    assert response.is_success()
    assert response.status == ProviderStatus.SUCCESS
    assert response.data['stars'] == 1200
    assert response.data['forks'] == 45
    assert response.data['open_issues'] == 7
    assert isinstance(response.fetched_at, str)
    assert response.fetched_at


def test_github_provider_network_error(monkeypatch):
    monkeypatch.setattr('oss_scorer.requests.get', lambda *args, **kwargs: (_ for _ in ()).throw(requests.ConnectionError('network fail')))

    provider = GitHubProvider({'github': {'timeout': 5, 'rate_limit': 100, 'token': ''}})
    response = provider.fetch('https://github.com/expressjs/express')

    assert response.status == ProviderStatus.NETWORK_ERROR
    assert response.error is not None
    assert response.error.provider == 'github'
    assert 'Network error' in response.error.message


def test_github_provider_cache_hit(monkeypatch):
    mock_get = MagicMock()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = {
        'stargazers_count': 100,
        'forks_count': 10,
        'pushed_at': '2025-01-01T00:00:00Z',
        'open_issues_count': 0,
        'contributors_url': 'https://api.github.com/repos/x/y/contributors',
    }
    mock_get.return_value = mock_response
    monkeypatch.setattr('oss_scorer.requests.get', mock_get)

    provider = GitHubProvider({'github': {'timeout': 5, 'rate_limit': 100, 'token': ''}})
    first = provider.fetch('https://github.com/expressjs/express')
    second = provider.fetch('https://github.com/expressjs/express')

    assert first.is_success()
    assert second.is_success()
    assert mock_get.call_count == 1
    assert first.fetched_at == second.fetched_at


def test_scorecard_provider_success(monkeypatch):
    mock_get = MagicMock()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = {
        'score': 8.2,
        'date': '2025-05-20',
        'checks': [
            {'name': 'Code-Review', 'score': 10},
            {'name': 'Branch-Protection', 'score': 8},
        ],
    }
    mock_get.return_value = mock_response
    monkeypatch.setattr('oss_scorer.requests.get', mock_get)

    provider = ScorecardProvider({'scorecard': {'timeout': 5}})
    response = provider.fetch('https://github.com/owner/repo')

    assert response.is_success()
    assert response.data['score'] == 8.2
    assert response.data['checks']['Code-Review'] == 10
    assert response.data['checks']['Branch-Protection'] == 8


def test_scorecard_provider_404_returns_network_error(monkeypatch):
    mock_response = MagicMock()
    mock_response.status_code = 404
    mock_response.raise_for_status.side_effect = requests.HTTPError(response=mock_response)
    monkeypatch.setattr('oss_scorer.requests.get', lambda *args, **kwargs: mock_response)

    provider = ScorecardProvider({'scorecard': {'timeout': 5}})
    response = provider.fetch('https://github.com/owner/repo')

    assert response.status == ProviderStatus.NETWORK_ERROR
    assert response.error is not None
    assert response.error.provider == 'scorecard'
    assert 'HTTP error 404' in response.error.message
