#!/usr/bin/env python3
"""Security gate for devsecops-pipeline.

  gate.py normalize <tool> <raw-report.json> <out-dir>
      Turns one scanner's JSON report into  <out-dir>/findings.json  and  <out-dir>/junit.xml
      (CodeBuild test report). Applies .security/exceptions.yml. Never fails the build.

  gate.py summary <results-dir> <out-html> --tools secrets,sast,sca,iac[,dast] [--title TEXT]
      Reads <results-dir>/<tool>/findings.json for every tool, writes the summary page and
      summary.json, and exits 1 when any finding is blocking or a required scan is missing.

Blocking = severity at or above FAIL_ON (env, default HIGH) and not covered by a valid exception.
Tools: gitleaks, semgrep, bandit, trivy, checkov, zap (several can be merged into one scan, e.g. sast).
"""
import datetime
import html
import json
import os
import sys
from xml.sax.saxutils import escape as xml_escape

SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
FAIL_ON = os.environ.get("FAIL_ON", "HIGH").upper()
EXCEPTIONS_FILE = os.environ.get("EXCEPTIONS_FILE", ".security/exceptions.yml")


def rank(sev):
    return SEVERITIES.index(sev) if sev in SEVERITIES else 0


# ---------------------------------------------------------------- parsers (raw JSON -> findings)
def f(tool, fid, sev, title, location, link=""):
    return {"tool": tool, "id": str(fid), "severity": sev.upper() if sev else "MEDIUM",
            "title": (title or "").strip(), "location": location or "", "link": link or ""}


def parse_gitleaks(data):
    return [f("gitleaks", x.get("RuleID"), "CRITICAL", x.get("Description") or "Secret in source code",
              f"{x.get('File')}:{x.get('StartLine')}") for x in (data or [])]


def parse_semgrep(data):
    sev_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
    out = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {}) or {}
        refs = meta.get("references") or [""]
        out.append(f("semgrep", r.get("check_id", "").split(".")[-1], sev_map.get(extra.get("severity"), "MEDIUM"),
                     extra.get("message"), f"{r.get('path')}:{r.get('start', {}).get('line')}",
                     refs[0] if isinstance(refs, list) else refs))
    return out


def parse_bandit(data):
    return [f("bandit", r.get("test_id"), r.get("issue_severity"), f"{r.get('test_name')}: {r.get('issue_text')}",
              f"{r.get('filename')}:{r.get('line_number')}", r.get("more_info"))
            for r in data.get("results", [])]


def parse_trivy(data):
    out = []
    for res in data.get("Results", []) or []:
        for v in res.get("Vulnerabilities", []) or []:
            fixed = v.get("FixedVersion") or "no fix yet"
            out.append(f("trivy", v.get("VulnerabilityID"), v.get("Severity"),
                         f"{v.get('PkgName')} {v.get('InstalledVersion')} (fixed in {fixed}): {v.get('Title', '')}",
                         res.get("Target"), v.get("PrimaryURL")))
    return out


def parse_checkov(data):
    reports = data if isinstance(data, list) else [data]
    out = []
    for rep in reports:
        if not isinstance(rep, dict):
            continue
        for c in rep.get("results", {}).get("failed_checks", []) or []:
            # without a Prisma Cloud key Checkov reports no severity: treat every failed check as HIGH
            out.append(f("checkov", c.get("check_id"), c.get("severity") or "HIGH", c.get("check_name"),
                         f"{c.get('file_path', '').lstrip('/')} {c.get('resource')}", c.get("guideline")))
    return out


def parse_zap(data):
    risk = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}
    out = []
    for site in data.get("site", []) or []:
        for a in site.get("alerts", []) or []:
            inst = a.get("instances", []) or []
            where = (inst[0].get("uri") if inst else site.get("@name")) + (f" (+{len(inst) - 1} more)" if len(inst) > 1 else "")
            out.append(f("zap", a.get("pluginid"), risk.get(str(a.get("riskcode")), "LOW"), a.get("alert") or a.get("name"),
                         where, f"https://www.zaproxy.org/docs/alerts/{a.get('pluginid')}/"))
    return out


PARSERS = {"gitleaks": parse_gitleaks, "semgrep": parse_semgrep, "bandit": parse_bandit,
           "trivy": parse_trivy, "checkov": parse_checkov, "zap": parse_zap}


# ---------------------------------------------------------------- exceptions
def load_exceptions():
    if not os.path.exists(EXCEPTIONS_FILE):
        return []
    import yaml  # PyYAML
    with open(EXCEPTIONS_FILE, encoding="utf-8") as fh:
        return (yaml.safe_load(fh) or {}).get("exceptions", []) or []


def apply_exceptions(findings, exceptions):
    today = datetime.date.today()
    for fd in findings:
        fd["excepted"], fd["exception"] = False, ""
        for ex in exceptions:
            if ex.get("tool") != fd["tool"] or str(ex.get("id")) != fd["id"]:
                continue
            if ex.get("location") and ex["location"] not in fd["location"]:
                continue
            expires = ex.get("expires")
            if isinstance(expires, str):
                expires = datetime.date.fromisoformat(expires)
            if expires and expires < today:
                fd["exception"] = f"exception EXPIRED on {expires} - finding is active again"
                continue
            fd["excepted"] = True
            fd["exception"] = f"{ex.get('reason', '')} (owner: {ex.get('owner', '?')}, expires {expires})"
            break
        fd["blocking"] = (not fd["excepted"]) and rank(fd["severity"]) >= rank(FAIL_ON)
    return findings


# ---------------------------------------------------------------- outputs
def write_junit(path, suite, findings):
    cases = []
    for fd in findings:
        name = xml_escape(f"[{fd['severity']}] {fd['id']} - {fd['title'][:150]}", {'"': "&quot;"})
        cls = xml_escape(fd["location"] or suite, {'"': "&quot;"})
        msg = xml_escape(f"{fd['location']} {fd['link']}".strip(), {'"': "&quot;"})
        if fd["blocking"]:
            body = f'<failure message="blocking: severity {fd["severity"]} >= {FAIL_ON}">{msg}</failure>'
        elif fd["excepted"]:
            body = f'<skipped message="accepted exception: {xml_escape(fd["exception"], {chr(34): "&quot;"})}"/>'
        else:
            body = f'<skipped message="severity {fd["severity"]} below {FAIL_ON} - reported, not blocking"/>'
        cases.append(f'  <testcase classname="{cls}" name="{name}">{body}</testcase>')
    if not cases:
        cases.append(f'  <testcase classname="{suite}" name="no findings"/>')
    failures = sum(1 for x in findings if x["blocking"])
    skipped = sum(1 for x in findings if not x["blocking"])
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(f'<?xml version="1.0" encoding="UTF-8"?>\n<testsuite name="{suite}" tests="{len(cases)}" '
                 f'failures="{failures}" skipped="{skipped}">\n' + "\n".join(cases) + "\n</testsuite>\n")


def cmd_normalize(tool, raw_path, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    try:
        with open(raw_path, encoding="utf-8") as fh:
            text = fh.read().strip()
        data = json.loads(text) if text else ([] if tool == "gitleaks" else {})
    except FileNotFoundError:
        print(f"{tool}: report {raw_path} not found - scanner did not produce output", file=sys.stderr)
        return 1
    findings = apply_exceptions(PARSERS[tool](data), load_exceptions())
    path = os.path.join(out_dir, "findings.json")
    existing = json.load(open(path, encoding="utf-8")) if os.path.exists(path) else []
    merged = [x for x in existing if x["tool"] != tool] + findings      # several tools can share one scan dir
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(merged, fh, indent=2)
    write_junit(os.path.join(out_dir, f"junit-{tool}.xml"), tool, findings)
    blocking = sum(1 for x in findings if x["blocking"])
    print(f"{tool}: {len(findings)} findings, {blocking} blocking (FAIL_ON={FAIL_ON})")
    for x in findings:
        mark = "BLOCK" if x["blocking"] else ("excepted" if x["excepted"] else "info")
        print(f"  [{mark:8}] {x['severity']:8} {x['id']:20} {x['location']}  {x['title'][:90]}")
    return 0


SCAN_LABELS = {"secrets": "Secret scan (Gitleaks)", "sast": "SAST (Semgrep + Bandit)",
               "sca": "Dependencies / SCA (Trivy) + SBOM", "iac": "IaC scan (Checkov)", "dast": "DAST (OWASP ZAP baseline)"}
SEV_COLOR = {"CRITICAL": "#7a0019", "HIGH": "#b42318", "MEDIUM": "#b54708", "LOW": "#475467", "INFO": "#667085"}


def cmd_summary(results_dir, out_html, tools, title):
    rows, details, overall_block = [], [], 0
    summary = {"title": title, "fail_on": FAIL_ON, "generated": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ"), "scans": {}}
    for scan in tools:
        path = os.path.join(results_dir, scan, "findings.json")
        if not os.path.exists(path):
            overall_block += 1
            summary["scans"][scan] = {"status": "MISSING"}
            rows.append(f"<tr><td>{SCAN_LABELS.get(scan, scan)}</td><td class='bad'>NOT RUN</td><td colspan='6'>"
                        f"no results - the scan failed or did not run</td></tr>")
            continue
        findings = json.load(open(path, encoding="utf-8"))
        counts = {s: sum(1 for x in findings if x["severity"] == s and not x["excepted"]) for s in SEVERITIES}
        blocking = sum(1 for x in findings if x["blocking"])
        excepted = sum(1 for x in findings if x["excepted"])
        overall_block += blocking
        status = "FAIL" if blocking else "PASS"
        summary["scans"][scan] = {"status": status, "blocking": blocking, "excepted": excepted, "counts": counts}
        links = " ".join(f"<a href='{scan}/{n}'>{n}</a>" for n in sorted(os.listdir(os.path.join(results_dir, scan)))
                         if n.endswith((".html", ".sarif", ".json")) and n != "findings.json")
        rows.append(f"<tr><td>{SCAN_LABELS.get(scan, scan)}</td><td class='{'bad' if blocking else 'ok'}'>{status}</td>"
                    + "".join(f"<td>{counts[s] or ''}</td>" for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
                    + f"<td>{excepted or ''}</td><td>{links}</td></tr>")
        items = "".join(
            f"<tr class='{'blk' if x['blocking'] else ''}'><td style='color:{SEV_COLOR.get(x['severity'])}'><b>{x['severity']}</b></td>"
            f"<td>{html.escape(x['tool'])}</td><td>{html.escape(x['id'])}</td><td>{html.escape(x['location'])}</td>"
            f"<td>{html.escape(x['title'])}{' <a href=' + html.escape(x['link'], quote=True) + '>more</a>' if x['link'] else ''}"
            f"{'<br><i>' + html.escape(x['exception']) + '</i>' if x['exception'] else ''}</td>"
            f"<td>{'BLOCKING' if x['blocking'] else ('accepted' if x['excepted'] else 'reported')}</td></tr>"
            for x in sorted(findings, key=lambda z: (-rank(z["severity"]), z["tool"])))
        details.append(f"<h2>{SCAN_LABELS.get(scan, scan)}</h2>" + (
            f"<table><tr><th>Severity</th><th>Tool</th><th>Rule / CVE</th><th>Where</th><th>Finding</th><th>Gate</th></tr>{items}</table>"
            if findings else "<p class='ok'>No findings.</p>"))
    verdict = "BLOCKED - fix the blocking findings or add a justified exception" if overall_block else "PASSED - no blocking findings"
    summary["verdict"] = "BLOCKED" if overall_block else "PASSED"
    page = f"""<!doctype html><html><head><meta charset="utf-8"><title>{html.escape(title)}</title><style>
body{{font-family:system-ui,sans-serif;margin:32px;color:#1d2433}}table{{border-collapse:collapse;width:100%;margin:8px 0 24px}}
th,td{{border:1px solid #d0d5dd;padding:6px 8px;text-align:left;font-size:14px;vertical-align:top}}th{{background:#f2f4f7}}
.ok{{color:#067647;font-weight:700}}.bad{{color:#b42318;font-weight:700}}.blk{{background:#fef3f2}}
.verdict{{font-size:20px;padding:12px 16px;border-radius:8px;background:{'#fef3f2' if overall_block else '#ecfdf3'}}}
</style></head><body><h1>{html.escape(title)}</h1>
<p class="verdict {'bad' if overall_block else 'ok'}">{verdict}</p>
<p>Gate: findings at or above <b>{FAIL_ON}</b> block the release unless listed in <code>.security/exceptions.yml</code>
with a reason, owner and expiry date. Generated {summary['generated']}.</p>
<table><tr><th>Scan</th><th>Result</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Accepted</th><th>Reports</th></tr>
{''.join(rows)}</table>{''.join(details)}</body></html>"""
    os.makedirs(os.path.dirname(out_html) or ".", exist_ok=True)
    with open(out_html, "w", encoding="utf-8") as fh:
        fh.write(page)
    with open(os.path.join(os.path.dirname(out_html) or ".", "summary.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
    print(f"{summary['verdict']}: " + ", ".join(f"{k}={v['status']}" for k, v in summary["scans"].items()))
    return 1 if overall_block else 0


def main(argv):
    if len(argv) >= 4 and argv[0] == "normalize":
        return cmd_normalize(argv[1], argv[2], argv[3])
    if len(argv) >= 3 and argv[0] == "summary":
        tools = ["secrets", "sast", "sca", "iac"]
        title = "Security summary"
        if "--tools" in argv:
            tools = argv[argv.index("--tools") + 1].split(",")
        if "--title" in argv:
            title = argv[argv.index("--title") + 1]
        return cmd_summary(argv[1], argv[2], tools, title)
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
