# 🔐 Sapient Security Insights

## 📖 Introduction

**Sapient Security Insight Platform (Sapient)** is an **AI-powered Kubernetes & Cloud Security Auditor**.  
It integrates **Kubescape** and **Trivy** with **LLMs** to generate **persona-based security insights** from your manifests.

---

### ✨ Why Sapient?
- ⚙️ Automates repetitive security checks on Kubernetes and IaC files  
- 👨‍💻 Produces reports tailored to developers, auditors, security engineers, and executives  
- 📊 Maps findings to compliance frameworks (SOC 2, PCI DSS, ISO 27001, NIST, RBI)  
- 🚀 Can run locally, or via Docker with zero friction  

---

### 💡 Core Philosophy
- 🏠 **Local-first** → No sensitive data leaves your environment  
- 🎭 **Persona-driven** → Insights are customized for the intended audience  
- 📑 **Auditor-ready** → Outputs are structured for compliance evidence  

---

## 🔒 Licensing & Privacy

Sapient uses a **license-based model** to control access and ensure fair use.  
The platform is designed to be **privacy-focused** and **local-first**.

### 📝 How Licensing Works
1. **Request a  Community License**  
   👉 [Sapient License Request Form](https://www.rohitchaurasia.com/sapient-license-form)  
   Complete the form to receive a `license.json` file.

   The license file contains:
   - 📧 Licensed email  
   - 🎟 License tier (Community)  
   - 📅 Expiry date
  

That’s it. **No manifests, no scan results, no ongoing telemetry is collected.**

- If the server responds with **“valid”**, the license is cached locally inside your container
- If the license is **expired or invalid**, Sapient disables scanning until a valid license is provided.  

### 🔐 Why Validation is Necessary
1. **Fair Use**  
   Prevents misuse of free community licenses in commercial environments.  

2. **Security & Authenticity**  
   Ensures your license file hasn’t been tampered with.  

3. **Sustainability**  
   Supports ongoing development by distinguishing between community and commercial users.  

### 🔒 Privacy Promise
- 🏠 **Local-first**: All scanning (Kubescape, Trivy) and AI analysis is done inside your environment.  
- 🚫 **No telemetry**: No ongoing metrics, analytics data is collected
- 🔑 **Only one outbound call**: To validate license authenticity at the time of activation.  

## ⚡ Installation

Sapient can run either via **Docker (preferred)** or **local Python environment**.

### 🐳 Option 1: Run via Docker (Recommended)

📥 Pull the prebuilt image:

```bash
docker pull rohitchaurasia/sapient-security:latest

```

▶️ Run it (Linux/Mac):

```bash
docker run -it -p 5000:5000 rohitchaurasia/sapient-security:latest

💻 On Windows (PowerShell/CMD)

```bash
docker run -it -p 5000:5000 rohitchaurasia/sapient-security:latest

Now open 👉 http://localhost:5000


🔑 Setting Your OpenAI API Key

You have two options:

### From the Web UI (Recommended)

-Start the container without any API key
-Open http://localhost:5000
-Follow instructions on screen to attach your license file
-Navigate to the ⚙️ Configuration tab
-Paste your API key and save → it updates the .env inside the container

💡 This means you don’t have to pass your key at runtime  the frontend handles it.


### Environment Variable at Run-Time
```bash
git clone https://github.com/rohitchaurasia/sapient-security.git
cd sapient-security
pip install -r requirements.txt
cp .env.example .env
nano .env (add keys)
python3 sapient.py

Followed by:
-Open http://localhost:5000
-Follow instructions on screen to attach your license file
-Navigate to the ⚙️ Configuration tab
-Paste your API key and save → it updates the .env inside the container


🎭 Personas (The Sapient Difference)

Sapient’s killer diffrentiator is that it doesn’t just dump scanner output.
Instead, it translates technical findings into reports tailored to specific personas in your organization.

👨‍💻 Developer (Engineering Teams)
✅ Focus: Actionable remediation

📌 Example Output:
“Privileged container detected → remove securityContext.privileged: true”
Code snippets & config samples to fix issues
Quick validation steps (e.g., kubectl describe pod)

🚀 Value: Developers don’t waste time parsing audits, they get copy-paste fixes.

🛡 Security Team (Control Testers / AppSec)
✅ Focus: Deep technical security assessment

📌 Example Output:
Full misconfig explanation & attack path
Probing questions to test controls (with positive/negative responses)
Mapping to OWASP Kubernetes Top Ten + compliance frameworks
Namespace/cluster impact analysis

🚀 Value: Security teams get detailed playbooks they can validate and share with engineers.

📋 Risk Analyst (GRC / Compliance)
✅ Focus: Audit-ready evidence

📌 Example Output:
Risk synopsis with CVSS-like scoring
Compliance mapping tables (PCI DSS, SOC 2, ISO 27001, NIST)
Threat model context (attacker type, business impact)
Residual risk & exception guidance

🚀 Value: Risk/Compliance teams can directly plug into audits without manual mapping.

🏛 Leadership (CISO / Executives / Board)
✅ Focus: Business risk visibility

📌 Example Output:
5-sentence executive summary of risk posture
3–5 key risk themes with plain-language impact (financial, reputational, compliance)
Strategic recommendations (investments, policies, automation)
Compliance alignment in one glance

🚀 Value: Executives get clarity, not noise — no YAML or CVEs, just business impact.

📊 Features
🔎 Multi-tool scanning (Kubescape + Trivy)
🎭 Persona-based reports (Dev, Sec, Risk, Leadership)
🖥 Web UI (drag & drop manifests, tailored reports)
📤 Export as PDF
🧩 REST API endpoints 
🔒 License system with remote validation

🌐 API Reference
GET /health → health check
POST /scan → upload manifests & persona, get report
POST /api/save_key → save API key from frontend
POST /api/validate_license → validate license JSON


📜 TL;DR License
✅ Free for personal & educational use
💼 Commercial use is prohibited
🚫 No resale, relicensing, or reverse engineering

See license.txt for more details.
