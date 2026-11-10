"""Tests for security/gate.py with sample reports in each scanner's JSON format. Run: python -m pytest tests/security"""
import json
import os
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
GATE = os.path.join(ROOT, "security", "gate.py")

SAMPLES = {
    "gitleaks": [{"RuleID": "generic-api-key", "Description": "Detected a Generic API Key", "File": "src/settings.py",
                  "StartLine": 3, "Secret": "REDACTED"}],
    "semgrep": {"results": [{"check_id": "security.dom-xss-innerhtml", "path": "web/app.js", "start": {"line": 30},
                             "extra": {"severity": "ERROR", "message": "innerHTML", "metadata": {"references": ["https://x"]}}}],
                "errors": []},
    "bandit": {"results": [{"test_id": "B105", "test_name": "hardcoded_password_string", "issue_severity": "LOW",
                            "issue_text": "Possible hardcoded password", "filename": "src/app.py", "line_number": 9,
                            "more_info": "https://bandit"}]},
    "trivy": {"Results": [{"Target": "requirements.txt", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2020-14343", "PkgName": "pyyaml", "InstalledVersion": "5.3", "FixedVersion": "5.4",
         "Severity": "CRITICAL", "Title": "arbitrary code execution", "PrimaryURL": "https://avd"},
        {"VulnerabilityID": "CVE-2000-0001", "PkgName": "x", "InstalledVersion": "1", "Severity": "MEDIUM"}]}]},
    "zap": {"site": [{"@name": "http://site", "alerts": [
        {"pluginid": "10038", "alert": "Content Security Policy (CSP) Header Not Set", "riskcode": "2",
         "instances": [{"uri": "http://site/"}, {"uri": "http://site/app.js"}]}]}]},
    "checkov": {"check_type": "cloudformation", "results": {"failed_checks": [
        {"check_id": "CKV_AWS_54", "check_name": "block public policy", "file_path": "/app.yaml",
         "resource": "AWS::S3::Bucket.WebsiteBucket", "severity": None},
        {"check_id": "CKV_AWS_999", "check_name": "made-up failing check", "file_path": "/app.yaml",
         "resource": "AWS::S3::Bucket.Other", "severity": None}]}},
}


def run(*args, cwd=ROOT):
    return subprocess.run([sys.executable, GATE, *args], cwd=cwd, capture_output=True, text=True)


def normalize(tmp_path, tool, scan):
    raw = tmp_path / f"{tool}.json"
    raw.write_text(json.dumps(SAMPLES[tool]))
    r = run("normalize", tool, str(raw), str(tmp_path / "results" / scan))
    assert r.returncode == 0, r.stderr
    return json.loads((tmp_path / "results" / scan / "findings.json").read_text())


def test_each_parser_and_gate(tmp_path):
    assert normalize(tmp_path, "gitleaks", "secrets")[0]["blocking"] is True           # secrets always CRITICAL
    sast = normalize(tmp_path, "semgrep", "sast")
    assert sast[0]["id"] == "dom-xss-innerhtml" and sast[0]["blocking"] is True        # ERROR -> HIGH
    sast = normalize(tmp_path, "bandit", "sast")                                       # merged into the same scan
    assert {x["tool"] for x in sast} == {"semgrep", "bandit"}
    assert [x["blocking"] for x in sast if x["tool"] == "bandit"] == [False]           # LOW does not block
    sca = normalize(tmp_path, "trivy", "sca")
    assert [x["blocking"] for x in sca] == [True, False]                               # CRITICAL blocks, MEDIUM not
    assert normalize(tmp_path, "zap", "dast")[0]["severity"] == "MEDIUM"


def test_exceptions_apply_by_id_and_location(tmp_path):
    iac = normalize(tmp_path, "checkov", "iac")
    by_id = {x["id"]: x for x in iac}
    assert by_id["CKV_AWS_54"]["excepted"] is True and by_id["CKV_AWS_54"]["blocking"] is False
    assert by_id["CKV_AWS_999"]["blocking"] is True                                    # unknown check -> HIGH, blocks


def test_summary_blocks_and_passes(tmp_path):
    normalize(tmp_path, "zap", "dast")
    page = tmp_path / "results" / "index.html"
    assert run("summary", str(tmp_path / "results"), str(page), "--tools", "dast").returncode == 0
    normalize(tmp_path, "gitleaks", "secrets")
    r = run("summary", str(tmp_path / "results"), str(page), "--tools", "secrets,dast")
    assert r.returncode == 1 and "BLOCKED" in r.stdout
    assert json.loads((tmp_path / "results" / "summary.json").read_text())["scans"]["secrets"]["status"] == "FAIL"
    r = run("summary", str(tmp_path / "results"), str(page), "--tools", "secrets,sca")  # sca never ran
    assert r.returncode == 1 and "MISSING" in (tmp_path / "results" / "summary.json").read_text()
    junit = (tmp_path / "results" / "secrets" / "junit-gitleaks.xml").read_text()
    assert "<failure" in junit


def test_empty_reports_pass(tmp_path):
    for tool, scan, content in [("gitleaks", "secrets", ""), ("semgrep", "sast", '{"results": []}')]:
        raw = tmp_path / f"{tool}.json"
        raw.write_text(content)
        assert run("normalize", tool, str(raw), str(tmp_path / "r" / scan)).returncode == 0
    r = run("summary", str(tmp_path / "r"), str(tmp_path / "r" / "index.html"), "--tools", "secrets,sast")
    assert r.returncode == 0 and "PASSED" in r.stdout
