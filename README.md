# OSSPolicyGuard 🛡️

# OSSPolicyGuard 🛡️
**Lightweight Open-Source Component Governance**



## Features
- ✅ Policy-based automatic approval/rejection
- 🔍 GitHub/NVD integration for risk analysis
- 📊 Interactive visualization of component scores
- ⚡ Single-file implementation (`oss_scorer.py`)

## 🚀 Quick Start
1. **Install dependencies**:
   ```bash
   pip install -r requirements.txt


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

        ![Sample Output](screenshots/ComponentAnalysis.jpg)


        # Cell 3: Visualize results
        visualizer.create_dashboard(results)

         ![Sample Output](screenshots/Visualize Output Screenshot-1.jpg)
         ![Sample Output](screenshots/Visualize Output Screenshot-2.jpg)

        # Cell 4: Interactive tools
        visualizer.interactive_selector()


        ![Sample Output](screenshots/Visualizewr Interactive Output-1.jpg)


