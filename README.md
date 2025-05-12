# OSSPolicyGuard 🛡️

# OSSPolicyGuard 🛡️
**Lightweight Open-Source Component Governance**

![Workflow Visualization](screenshots/workflow.svg)

## Features
- ✅ Policy-based automatic approval/rejection
- 🔍 GitHub/NVD integration for risk analysis
- 📊 Interactive visualization of component scores
- ⚡ Single-file implementation (`oss_scorer.py`)

## 🚀 Quick Start
1. **Install dependencies**:
   ```bash
   pip install -r requirements.txt

![Sample Output](screenshots/output_sample.png)

1. **Install**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure** `config.yaml`:
   ```yaml
   github_token: "your_token"
   risk_threshold: 80
   ```

3. **Run**:


        # Cell 1: Initialization
        from oss_scorer import init_oss_analysis
        scorer, workflow, visualizer = init_oss_analysis()


        # Cell 2: Analyze a component
        sample_project = {
            "name": "express",
            "repo_url": "https://github.com/expressjs/express",
            "package_name": "express",
            "ecosystem": "npm",
            "criticality": "Business Critical"
        }

        results = workflow.evaluate_component(sample_project)
        display(results)

        # Cell 3: Visualize results
        visualizer.create_dashboard(results)

        # Cell 4: Interactive tools
        visualizer.interactive_selector()


## 📸 Workflow
![Approval Process](screenshots/workflow.png)