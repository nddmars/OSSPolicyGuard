import yaml
import pandas as pd
import yaml
import pandas as pd
import requests
from datetime import datetime
import matplotlib.pyplot as plt
from ipywidgets import interact, Dropdown
import ipywidgets as widgets
from IPython.display import display, Markdown
import json
from pathlib import Path

# Configuration Manager
class OSSConfig:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(OSSConfig, cls).__new__(cls)
            cls._instance._load_config()  # Changed to private method
        return cls._instance
    
    def _load_config(self):
        """Internal method to load configuration"""
        try:
            config_path = Path('config.yaml')
            if not config_path.exists():
                raise FileNotFoundError("config.yaml not found")
            
            with open(config_path) as f:
                self.config = yaml.safe_load(f) or {}  # Ensure config is always a dict
            
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
            
        except Exception as e:
            print(f"Config loading failed: {e}")
            self.config = {}  # Fallback empty config

# Main Scorer Implementation
class OSSScorer:
    def __init__(self):
        self.config = OSSConfig().config
        self.framework = self.create_oss_framework()
        self.proprietary = self.create_proprietary_additions()
        
    def create_oss_framework(self):
        weights = self.config['scoring']['weights']
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
            
            ["TOTAL SCORE", "100%", "0-100", f"A={self.config['scoring']['thresholds']['critical']}-100, B={self.config['scoring']['thresholds']['high']}-89, C={self.config['scoring']['thresholds']['medium']}-79, D={self.config['scoring']['thresholds']['low']}-69, F<60"]
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
            ["Corporate Entity", "Other Democracies", 10, multipliers['corporate']*1.2, "Medium risk multiplier"],
            ["Corporate Entity", "High-Risk Nations", 50, multipliers['corporate']*2.0, "High risk multiplier"],
            ["Verified Individual", "US/EU/5EYES", 10, multipliers['verified_individual'], "Medium risk multiplier"],
            ["Verified Individual", "Other Democracies", 20, multipliers['verified_individual']*1.25, "Elevated risk multiplier"],
            ["Verified Individual", "High-Risk Nations", 75, multipliers['verified_individual']*2.5, "Very high risk multiplier"],
            ["Anonymous", "US/EU/5EYES", 30, multipliers['anonymous'], "High baseline risk"],
            ["Anonymous", "Other Democracies", 50, multipliers['anonymous']*1.5, "Very high baseline risk"],
            ["Anonymous", "High-Risk Nations", 100, multipliers['anonymous']*3.0, "Extreme risk - avoid"]
        ]
        geo_risk_df = pd.DataFrame(geo_risk, columns=["Maintainer Type", "Location", "Risk Points", "Weight Multiplier", "Notes"])
        
        return {
            "Risk_Heat_Mapping": risk_heat_df,
            "Geopolitical_Risk_Matrix": geo_risk_df
        }
    
    def get_github_metrics(self, repo_url):
        """Fetch live GitHub metrics using API"""
        try:
            headers = {}
            if self.config['github']['token']:
                headers = {'Authorization': f'token {self.config["github"]["token"]}'}
            
            owner, repo = repo_url.rstrip('/').split('/')[-2:]
            repo_data = requests.get(
                f'https://api.github.com/repos/{owner}/{repo}',
                headers=headers,
                timeout=self.config['github']['timeout']
            ).json()
            
            return {
                'stars': repo_data.get('stargazers_count', 0),
                'forks': repo_data.get('forks_count', 0),
                'last_commit': repo_data.get('pushed_at', ''),
                'open_issues': repo_data.get('open_issues_count', 0),
                'contributors_url': repo_data.get('contributors_url', '')
            }
        except Exception as e:
            print(f"GitHub API Error: {e}")
            return None
    
    def check_cves(self, package_name, ecosystem="npm"):
        """Check NVD database for CVEs"""
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={package_name}"
            headers = {}
            if self.config['nvd']['api_key']:
                headers = {"apiKey": self.config["nvd"]["api_key"]}
            
            response = requests.get(
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
            return {'total': 0, 'critical': 0, 'last_updated': datetime.now().isoformat()}
        except Exception as e:
            print(f"NVD API Error: {e}")
            return {'total': 0, 'critical': 0, 'last_updated': datetime.now().isoformat()}

# Visualization and Interaction
class OSSVisualizer:
    def __init__(self, scorer):
        self.scorer = scorer
        
    def create_dashboard(self, project_data):
        plt.figure(figsize=(14, 8))
        
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
                [project_data['total_score'], 100-project_data['total_score']],
                labels=['Score', 'Risk Gap'],
                colors=[risk_colors.get(risk_level, '#FFC107'), '#E0E0E0'],
                startangle=90
            )
            plt.title(f"Risk Level: {risk_level}")
        
        plt.tight_layout()
        plt.show()
        
        # Display framework as table
        display(Markdown("### Scoring Framework"))
        display(self.scorer.framework.style.set_caption("Scoring Framework"))
        
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
        
    def evaluate_component(self, component_data):
        """Full evaluation pipeline"""
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
        
        # Calculate scores (simplified example - expand with your actual logic)
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
        
        # Determine approval
        criticality = component_data.get('criticality', 'Non-Critical')
        approval = self._determine_approval(total_score, criticality)
        
        results.update({
            'scores': scores,
            'weighted_scores': weighted_scores,
            'total_score': total_score,
            'approval': approval,
            'risk_level': self._get_risk_level(total_score)
        })
        
        return results
    
    def _calculate_activity_score(self, results):
        """Calculate activity score (0-100) based on GitHub metrics"""
        # Placeholder - implement your actual scoring logic
        return 80
    
    def _calculate_security_score(self, results):
        """Calculate security score (0-100) based on CVEs and practices"""
        base_score = 100
        if 'cve_data' in results:
            base_score -= results['cve_data']['critical'] * 5  # Deduct 5 points per critical CVE
        return max(0, min(100, base_score))
    
    def _calculate_trust_score(self, results):
        """Calculate trustworthiness score (0-100)"""
        # Placeholder - implement based on maintainer info
        return 70
    
    def _calculate_community_score(self, results):
        """Calculate community/adoption score (0-100)"""
        if 'github_metrics' in results:
            stars = results['github_metrics']['stars']
            if stars > 10000: return 100
            elif stars > 1000: return 80
            elif stars > 100: return 60
        return 40
    
    def _determine_approval(self, score, criticality):
        thresholds = self.config['scoring']['thresholds']
        
        rules = {
            "Mission Critical": {
                (thresholds['critical'], 100): "APPROVED",
                (thresholds['high'], thresholds['critical']-0.1): "REVIEW BOARD",
                (0, thresholds['high']-0.1): "PROHIBITED"
            },
            "Business Critical": {
                (thresholds['high'], 100): "APPROVED",
                (thresholds['medium'], thresholds['high']-0.1): "MITIGATION REQUIRED",
                (0, thresholds['medium']-0.1): "PROHIBITED"
            },
            "Non-Critical": {
                (thresholds['medium'], 100): "AUTO-APPROVED",
                (thresholds['low'], thresholds['medium']-0.1): "APPROVED",
                (0, thresholds['low']-0.1): "MITIGATION REQUIRED"
            }
        }
        
        for (min_score, max_score), status in rules.get(criticality, {}).items():
            if min_score <= score <= max_score:
                return status
        return "REVIEW REQUIRED"
    
    def _get_risk_level(self, score):
        thresholds = self.config['scoring']['thresholds']
        if score >= thresholds['critical']: return "Low"
        elif score >= thresholds['high']: return "Medium-Low"
        elif score >= thresholds['medium']: return "Medium"
        elif score >= thresholds['low']: return "Medium-High"
        else: return "High"

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
        display(Markdown(f"### Error: {str(e)}"))
        raise