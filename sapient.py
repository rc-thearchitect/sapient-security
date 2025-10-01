#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
K8s Auditor - Sapient Edition
- Scans uploaded manifest(s) with Kubescape and Trivy.
- Uses OpenAI to generate deeply differentiated, persona-based reports.
"""
import os
import json
import tempfile
import subprocess
import traceback
from typing import Any, Dict, Optional
from datetime import datetime

import requests
from dotenv import load_dotenv
from flask import Flask, request, jsonify, render_template

# --- Setup ---
load_dotenv()
app = Flask(__name__, template_folder=".", static_folder="static")

# --- Configuration ---
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
KUBESCAPE_CMD = os.getenv("KUBESCAPE_CMD", "kubescape")
TRIVY_CMD = os.getenv("TRIVY_CMD", "trivy")
LICENSE_FILE = os.path.join(os.path.dirname(__file__), 'license.json')
LICENSE_VALIDATION_URL = "https://5g5d5cv96k.execute-api.ap-south-1.amazonaws.com/prod/validate"
ENV_FILE = os.path.join(os.path.dirname(__file__), '.env')

# --- Helper Functions ---
def _is_licensed() -> bool:
    """Checks if a valid license.json file exists."""
    return os.path.exists(LICENSE_FILE)

def _has_openai_key() -> bool:
    """Checks if the OpenAI API key is set in the environment or .env file."""
    load_dotenv(ENV_FILE)  # Reload to get latest values
    return bool(os.getenv("OPENAI_API_KEY"))

def _validate_license_api(license_data: Dict) -> tuple[Optional[Dict], Optional[str]]:
    """Sends license data to the validation endpoint."""
    try:
        response = requests.post(LICENSE_VALIDATION_URL, json=license_data, timeout=15)
        response.raise_for_status()
        return response.json(), None
    except requests.exceptions.RequestException as e:
        return None, f"API request failed: {e}"
    except json.JSONDecodeError:
        return None, "Invalid response from validation server."

# --- Scanning Logic ---
def _run_command(cmd: list, timeout: int = 180) -> tuple[int, str, str]:
    """Runs a command and captures its output."""
    try:
        process = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return process.returncode, process.stdout, process.stderr
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}. Please ensure it's installed and in your PATH."
    except subprocess.TimeoutExpired:
        return -2, "", "Command timed out"

def run_kubescape_on_file(path: str) -> tuple[Optional[Dict], Optional[str]]:
    """Runs Kubescape on a given file path."""
    cmd = [KUBESCAPE_CMD, "scan", "framework", "nsa", "--format", "json", path]
    rc, stdout, stderr = _run_command(cmd)
    if not stdout.strip() and rc != 0:
        return None, f"Kubescape execution failed (rc={rc}): {stderr or 'No output'}"
    try:
        return json.loads(stdout), None
    except json.JSONDecodeError:
        return None, f"Failed to parse Kubescape JSON output. Stderr: {stderr}"

def run_trivy_on_file(path: str) -> tuple[Optional[Dict], Optional[str]]:
    """Runs Trivy on a given file path."""
    cmd = [TRIVY_CMD, "config", "--format", "json", "--severity", "HIGH,CRITICAL", path]
    rc, stdout, stderr = _run_command(cmd)
    if rc != 0 and not stdout.strip():
        return None, f"Trivy failed (rc={rc}): {stderr or stdout}"
    try:
        if not stdout.strip() or "null" in stdout:
            return {"Results": []}, None
        return json.loads(stdout), None
    except json.JSONDecodeError:
        return None, f"Failed to parse Trivy JSON output. Stderr: {stderr}"

# --- AI Report Generation ---
def summarize_findings(raw_json: Optional[Dict], tool_name: str, max_len: int = 8000) -> str:
    """Summarizes or truncates JSON output from scanning tools."""
    if not raw_json:
        return f"No output received from {tool_name}."
    full_text = json.dumps(raw_json, indent=2)
    if len(full_text) > max_len:
        return full_text[:max_len] + "\n\n[... output truncated ...]"
    return full_text


PERSONA_PROMPTS = {
    "risk_analyst": """
    You are a GRC (Governance, Risk, and Compliance) Analyst. Your report MUST be in Markdown and serve as audit evidence. The report should be titled Kubernetes Security Audit (Risk Analyst)

    **Structure:**
    1.  **Risk Synopsis:** Start with a quantified risk rating (high,medium,low,with  CVSS-like score) and provide rationale for rating.
    2.  **Compliance Mapping Table:** Detailed table with columns: `Finding ID`, `Description`, `Severity`, `Affected Controls (e.g., PCI-DSS 3.2.1, NIST AC-3, SOC2 CC6.1)`.
    3.  **OWASP & Framework Alignment:** Map critical/high findings to OWASP Kubernetes Top Ten and at least one compliance framework (CIS, ISO 27001, NIST, PCI-DSS).
    4.  **Threat Model Context:** For all findings, describe an attack vector, attacker type, and potential business impact.
    5.  **Residual Risk & Exceptions:** Highlight risks, areas requiring formal risk exceptions,controls that can mitigate the risk.
    6.  **Risk Mitigation Recommendations:** Frame recommendations in terms of reducing risk per finding. Provide concluding paragraph summarizing report.

    **Tone & Content:**
    - BE formal, precise, and objective.
    - DO focus on providing clear, traceable evidence for auditors.
    - DO map findings to at least one major compliance framework (NIST, PCI-DSS, SOC 2, ISO 27001).
    """,

    "leadership": """
    You are a CISO preparing a report for an executive board. Your response MUST be in Markdown.

    **Structure:**
    1.  **Executive Summary:** 5-sentence overview of Kubernetes security posture, including overall risk level (Critical/High/Medium/Low).
    2.  **Key Risk Themes & Business Impact:** Present 2–5 risk themes (e.g., "Publicly Exposed Services," "Unpatched Images"). For each, explain the financial, reputational, and compliance risk in plain language.
    3.  **Compliance & OWASP Mapping:** Add a concise table showing how current risks align with OWASP Kubernetes Top Ten and compliance frameworks (PCI-DSS, SOC2, CIS). This demonstrates industry and regulatory alignment.
    4.  **Strategic Recommendations:** Bulleted list of 3–5 high-level actions (e.g., resource investments, policy changes, automation priorities).
    5.  **Forward-Looking Statement:** A closing note summarizing the report & recommending improvements (e.g., migration to hardened base images, rollout of policy-as-code).

    **Tone & Content:**
    - AVOID deep technical jargon, CVEs, or code snippets.
    - DO translate technical findings into business risk (financial, reputational, operational).
    - DO use strong, direct language suitable for board-level reporting.
    """,

    "security_team": """
    You are a Kubernetes Security Engineer creating a report for your technical security peers and control testers. Your response MUST be in Markdown.

    **Structure:**
    1.  **Technical Summary:** Overview of findings, number of critical/high issues per scanner, and main risk categories (e.g., RBAC, Pod Security, Supply Chain).
    2.  **Prioritized Findings & Investigation Playbook:** For EACH high/critical finding, include:
        - **Finding:** Clear title (e.g., "Privileged Container Detected").
        - **Severity:** Critical/High/Medium/Low.
        - **Technical Explanation:** Detailed misconfiguration/vulnerability description and potential attack path.
        - **Probing Questions & Indicative Responses:** 2–5 validation questions with examples of "Positive Response" and "Negative Response" responses.
        - **OWASP & Compliance Mapping:** Map the issue to OWASP Kubernetes Top Ten and relevant compliance controls.
        - **Remediation Guidance:** Concise technical fix or pointer to playbooks/runbooks.
    3.  **Cluster/Namespace Impact Overview:** Summarize which clusters/namespaces are most affected, highlighting hotspots.
    4.  **Manifest Content Analysis:** **This is a critical section.** Manually review the full manifest provided. Identify any potential logical flaws in the configuration that the automated scanners might miss. Examples include overly permissive network policies, insecure Ingress routing, or secrets that are unnecessarily exposed between namespaces. Detail these logical flaws here.
    5.  **Next Steps & Ownership:** Actionable to-do list with responsible teams (e.g., DevOps, SRE, AppSec).

    **Tone & Content:**
    - BE highly technical, precise, and exhaustive for each major finding.
    - DO NOT just provide a table; the value is in the per-finding playbook and detailed guidance.
    """,

    "dev_team": """
    You are a Senior Developer creating a remediation-focused report for an engineering team. Your response MUST be in Markdown.

    **Structure:**
    1.  **Action Summary:** Bulleted list of the most urgent, actionable tasks (with affected services/workloads named explicitly).
    2.  **Remediation Playbook:** For each issue:
        - **What is the issue?** (1-sentence explanation).
        - **Why does it matter?** (1-sentence impact statement).
        - **How to fix it:** Actionable code snippet, manifest example, or package version update.
        - **Validation Step:** Simple test/command to confirm the fix is applied (e.g., `kubectl describe pod ...`).
    3.  **Best Practice Nudges:** 1–2 preventative measures for CI/CD (e.g., add image scanning in pipeline, enforce PodSecurityAdmission).
    4.  **Knowledge Sharing:** Suggest links to documentation, internal runbooks, or relevant OWASP references for developers to learn from.
    5.  **Developer-Friendly Metrics:** Show “issues fixed vs. remaining” in terms of dev-owned tasks.

    **Tone & Content:**
    - BE direct and focused entirely on remediation.
    - DO provide copy-pasteable code snippets and commands.
    - AVOID strategy, compliance-heavy language, or management framing.
    """
}

def get_persona_prompt(persona: str) -> str:
    """Returns the prompt for the specified persona."""
    return PERSONA_PROMPTS.get(persona, PERSONA_PROMPTS["security_team"])

def generate_report(manifest_text: str, kubescape_results: Optional[Dict], trivy_results: Optional[Dict], persona: str) -> str:
    """Generates an AI report based on scan results and persona."""
    system_prompt = get_persona_prompt(persona)
    kubescape_summary = summarize_findings(kubescape_results, "Kubescape")
    trivy_summary = summarize_findings(trivy_results, "Trivy")
    
    user_prompt = f"""Generate your persona-based report using the following tool outputs and the full Kubernetes manifest provided.

### Full Manifest Content
```yaml
{manifest_text}
```

### Kubescape Results
```json
{kubescape_summary}
```

### Trivy Results
```json
{trivy_summary}
```"""

    try:
        if not _has_openai_key():
            return "## Configuration Error\n`OPENAI_API_KEY` is not set. Please add it in the Configuration tab."
        
        load_dotenv(ENV_FILE)
        import openai
        client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        
        response = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}],
            temperature=0.1,
            max_tokens=3500
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"## AI Report Generation Failed\nAn unexpected error occurred: {e}"

# --- Flask Routes ---
@app.route("/")
def index():
    """Serves the main HTML page."""
    return render_template("index.html")

@app.route("/api/status")
def status():
    """Returns the current status of the application."""
    license_data = None
    if _is_licensed():
        try:
            with open(LICENSE_FILE, 'r') as f:
                license_data = json.load(f)
        except (IOError, json.JSONDecodeError):
            pass

    return jsonify({
        "is_licensed": _is_licensed() and license_data is not None,
        "has_openai_key": _has_openai_key(),
        "license_details": license_data
    })

@app.route("/api/validate_license", methods=["POST"])
def validate_license():
    """Validates an uploaded license file."""
    if 'license' not in request.files:
        return jsonify({"status": "error", "error": "No license file provided."}), 400
    
    license_file = request.files['license']
    try:
        license_content = license_file.read().decode('utf-8-sig')
        if not license_content.strip():
            raise json.JSONDecodeError("File is empty or contains only whitespace.", license_content, 0)
            
        license_data = json.loads(license_content)
        validation_result, error = _validate_license_api(license_data)
        
        if validation_result and validation_result.get("status") == "valid":
            with open(LICENSE_FILE, 'w') as f:
                json.dump(validation_result, f)
            return jsonify({"status": "valid"})
        else:
            error_message = error or "License validation failed."
            return jsonify({"status": "invalid", "error": error_message}), 400
    except json.JSONDecodeError as e:
        return jsonify({"status": "error", "error": f"Invalid license file format: {e}"}), 400
    except Exception as e:
        return jsonify({"status": "error", "error": f"An unexpected error occurred: {e}"}), 500

@app.route("/api/save_key", methods=["POST"])
def save_key():
    """Saves the OpenAI API key to the .env file."""
    data = request.get_json()
    api_key = data.get('api_key')
    if not api_key:
        return jsonify({"error": "API key is missing."}), 400

    try:
        env_vars = {}
        if os.path.exists(ENV_FILE):
            with open(ENV_FILE, 'r') as f:
                for line in f:
                    if '=' in line:
                        key, value = line.strip().split('=', 1)
                        env_vars[key] = value
        
        env_vars['OPENAI_API_KEY'] = f'"{api_key}"'

        with open(ENV_FILE, 'w') as f:
            for key, value in env_vars.items():
                f.write(f"{key}={value}\n")
        
        os.environ['OPENAI_API_KEY'] = api_key
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"error": f"Failed to write to .env file: {e}"}), 500

@app.route("/scan", methods=["POST"])
def scan():
    """Handles file uploads, runs scans, and returns reports."""
    if not _is_licensed():
        return jsonify({"error": "Application is not licensed."}), 403
    if not _has_openai_key():
         return jsonify({"error": "OpenAI API key is not configured."}), 403

    try:
        if 'files' not in request.files:
            return jsonify({"error": "No files were uploaded."}), 400
        
        files = request.files.getlist('files')
        persona = request.form.get("persona", "security_team")
        filenames = request.form.get("filenames", "N/A")
        
        manifest_content = ""
        for file in files:
            manifest_content += file.read().decode('utf-8', 'ignore') + "\n---\n"

        if not manifest_content.strip():
            return jsonify({"error": "Uploaded files are empty."}), 400

        with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix=".yaml") as tmp:
            tmp.write(manifest_content)
            tmp_path = tmp.name

        try:
            kubescape_results, ks_error = run_kubescape_on_file(tmp_path)
            trivy_results, trivy_error = run_trivy_on_file(tmp_path)
            
            ai_report_md = generate_report(manifest_content, kubescape_results, trivy_results, persona)
            
            generation_date = datetime.now().strftime("%d-%m-%Y")
            cover_page_md = f"""
<div class="cover-page">
<img src="/static/logo.png" alt="Sapient Logo" class="cover-page-logo">
<h1>Security Audit Report</h1>
<p><strong>Files Scanned:</strong> {filenames}</p>
<p><strong>Date Generated:</strong> {generation_date}</p>
</div>

"""
            report_footer_md = """
<br>
---
<div class="report-footer">
<p>&copy; 2025 Sapient Security Auditor | Built by <a href="https://www.rohitchaurasia.com/" target="_blank">Rohit Chaurasia</a></p>
</div>
"""
            #  footer
            if ai_report_md and "##" in ai_report_md:
                 full_report = cover_page_md + ai_report_md + report_footer_md
            else:
                 full_report = cover_page_md + ai_report_md


            errors = [e for e in [ks_error, trivy_error] if e]
            
            return jsonify({
                "report": full_report,
                "raw_kubescape": kubescape_results or {"error": "No output"},
                "raw_trivy": trivy_results or {"error": "No output"},
                "errors": errors
            })
        finally:
            os.unlink(tmp_path)
    except Exception as e:
        error_details = traceback.format_exc()
        print(f"An unexpected error occurred:\n{error_details}")
        return jsonify({"error": "An unexpected server error occurred.", "details": str(e)}), 500

@app.route("/health")
def health():
    """Simple healthcheck endpoint for Docker."""
    return jsonify({"status": "ok"}), 200

if __name__ == "__main__":
    host = os.getenv("FLASK_RUN_HOST", "0.0.0.0")
    # Prefer PORT (Docker), fallback to FLASK_RUN_PORT, default 5000
    port = int(os.getenv("PORT", os.getenv("FLASK_RUN_PORT", "5000")))
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    app.run(host=host, port=port, debug=debug)
