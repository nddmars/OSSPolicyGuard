# OSSPolicyGuard - Requirements Document
**Version**: 1.0  
**Last Updated**: ${DATE}  

## 1. Overview
Automated policy-driven scoring system for open-source component governance with risk-based approval workflows.

## 2. Business Requirements
| ID | Requirement | Priority | Stakeholder |
|----|-------------|----------|-------------|
| BR-01 | Automatically approve/reject OSS components based on organizational policies | High | Security Team |
| BR-02 | Enforce geo-political risk rules for maintainer locations | High | Legal |
| BR-03 | Reduce manual security reviews by 60% through auto-classification | Medium | Engineering |

## 3. Technical Requirements
### 3.1 Core Scoring Engine
| ID | Requirement | Acceptance Criteria |
|----|-------------|---------------------|
| TR-01 | Policy-driven scoring | Supports YAML/JSON policy definitions with custom weights |
| TR-02 | CVE risk calculation | Integrates with NVD API (max 5s latency per component) |
| TR-03 | License compliance | Detects 50+ SPDX licenses with custom blacklists |

### 3.2 Workflow Automation
| ID | Requirement | Example |
|----|-------------|---------|
| TR-10 | Threshold-based routing | "Score ≥80 → Auto-approve" |
| TR-11 | JIRA integration | Auto-create tickets for legal review |
| TR-12 | Slack notifications | Alert channel when high-risk detected |

### 3.3 Integration Requirements
| ID | System | Authentication |
|----|--------|----------------|
| IR-01 | GitHub/GitLab | OAuth2 |
| IR-02 | NVD API | API Key |
| IR-03 | JIRA Cloud | PAT Tokens |

## 4. Policy Requirements
### 4.1 Scoring Dimensions
```yaml
dimensions:
  - security: 
      weight: 40% 
      subfactors: [cves, response_time]
  - legal: 
      weight: 30%
      subfactors: [licenses, geo_risk]