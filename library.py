"""
MITRE ATT&CK Detection Rules Library
A curated library of 40+ detection rules mapped to MITRE ATT&CK (Enterprise),
with translations to Sigma, Splunk SPL, Elastic ES|QL, and Microsoft Sentinel KQL.

Modes:
  python library.py list                 # list all rules
  python library.py search APT           # search by keyword
  python library.py show T1059.001       # show full rule details + queries
  python library.py export sigma out/    # export all rules in a given format
  python library.py coverage             # ATT&CK coverage heatmap (HTML)
  python library.py simulate samples/    # run against synthetic event logs

Author: Mohith Vasamsetti (CyberEnthusiastic)
"""
import os
import re
import sys
import json
import argparse
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Optional

from report_generator import generate_coverage_html


# -------------------------------------------------------------
# Rule library (subset of 40+ rules - illustrative)
# -------------------------------------------------------------
RULES = [
    {
        "id": "R-0001",
        "title": "PowerShell Encoded Command Execution",
        "description": "Detects powershell.exe launched with -EncodedCommand / -e(nc) which attackers use to obfuscate payloads.",
        "tactic": "Execution",
        "technique": "T1059.001",
        "technique_name": "Command and Scripting Interpreter: PowerShell",
        "severity": "HIGH",
        "confidence": 0.90,
        "data_source": "Windows Process Creation (4688 / Sysmon EID 1)",
        "references": ["https://attack.mitre.org/techniques/T1059/001/"],
        "sigma": {
            "detection": {
                "selection": {
                    "Image|endswith": "\\\\powershell.exe",
                    "CommandLine|contains": [" -enc ", " -EncodedCommand ", " -ec "],
                },
                "condition": "selection",
            },
        },
        "splunk": 'index=windows EventCode=4688 (Image="*\\\\powershell.exe" OR process_name="powershell.exe") (CommandLine="*-enc *" OR CommandLine="*-EncodedCommand*" OR CommandLine="* -ec *")',
        "elastic": 'process.name:"powershell.exe" AND process.command_line:(*-enc* OR *-EncodedCommand* OR *-ec*)',
        "kql": 'DeviceProcessEvents | where FileName =~ "powershell.exe" and (ProcessCommandLine has "-enc" or ProcessCommandLine has "-EncodedCommand" or ProcessCommandLine has " -ec ")',
    },
    {
        "id": "R-0002",
        "title": "Mimikatz / LSASS Memory Access",
        "description": "Detects processes opening LSASS with PROCESS_VM_READ / PROCESS_QUERY_INFORMATION access - classic credential dumping.",
        "tactic": "Credential Access",
        "technique": "T1003.001",
        "technique_name": "OS Credential Dumping: LSASS Memory",
        "severity": "CRITICAL",
        "confidence": 0.95,
        "data_source": "Sysmon EID 10 (ProcessAccess)",
        "references": ["https://attack.mitre.org/techniques/T1003/001/"],
        "sigma": {
            "detection": {
                "selection": {
                    "EventID": 10,
                    "TargetImage|endswith": "\\\\lsass.exe",
                    "GrantedAccess|re": "0x(1010|1410|1438|143A|1FFFFF).*",
                },
                "filter": {"SourceImage|endswith": ["\\\\svchost.exe", "\\\\WerFault.exe"]},
                "condition": "selection and not filter",
            },
        },
        "splunk": 'sourcetype=sysmon EventCode=10 TargetImage="*\\\\lsass.exe" GrantedAccess IN (0x1010,0x1410,0x1438,0x143a,0x1fffff) NOT SourceImage IN ("*\\\\svchost.exe","*\\\\WerFault.exe")',
        "elastic": 'event.code:"10" AND winlog.event_data.TargetImage:"*\\\\lsass.exe" AND winlog.event_data.GrantedAccess:("0x1010" OR "0x1410" OR "0x1438" OR "0x143a" OR "0x1fffff")',
        "kql": 'DeviceEvents | where ActionType == "OpenProcessApiCall" and InitiatingProcessFileName != "svchost.exe" and FileName =~ "lsass.exe"',
    },
    {
        "id": "R-0003",
        "title": "Suspicious Scheduled Task Creation via schtasks.exe",
        "description": "Detects persistence via schtasks.exe with /create and network or remote arguments.",
        "tactic": "Persistence",
        "technique": "T1053.005",
        "technique_name": "Scheduled Task/Job: Scheduled Task",
        "severity": "MEDIUM",
        "confidence": 0.80,
        "data_source": "Windows Process Creation",
        "references": ["https://attack.mitre.org/techniques/T1053/005/"],
        "sigma": {
            "detection": {
                "selection": {
                    "Image|endswith": "\\\\schtasks.exe",
                    "CommandLine|contains": ["/create", " /sc ", " /tn "],
                },
                "condition": "selection",
            },
        },
        "splunk": 'index=windows EventCode=4688 Image="*\\\\schtasks.exe" CommandLine="*/create*"',
        "elastic": 'process.name:"schtasks.exe" AND process.args:("/create" AND "/sc")',
        "kql": 'DeviceProcessEvents | where FileName =~ "schtasks.exe" and ProcessCommandLine has "/create"',
    },
    {
        "id": "R-0004",
        "title": "Suspicious BITS Job Created for Download (Living-off-the-land)",
        "description": "Adversaries use BITS (bitsadmin.exe) to silently download payloads.",
        "tactic": "Defense Evasion",
        "technique": "T1197",
        "technique_name": "BITS Jobs",
        "severity": "HIGH",
        "confidence": 0.85,
        "data_source": "Windows Process Creation",
        "references": ["https://attack.mitre.org/techniques/T1197/"],
        "sigma": {
            "detection": {
                "selection": {
                    "Image|endswith": "\\\\bitsadmin.exe",
                    "CommandLine|contains": ["transfer", "addfile", "/create"],
                },
                "condition": "selection",
            },
        },
        "splunk": 'index=windows EventCode=4688 Image="*\\\\bitsadmin.exe" CommandLine="*transfer*"',
        "elastic": 'process.name:"bitsadmin.exe" AND process.args:("transfer" OR "/create")',
        "kql": 'DeviceProcessEvents | where FileName =~ "bitsadmin.exe" and ProcessCommandLine has "transfer"',
    },
    {
        "id": "R-0005",
        "title": "Impacket-style Remote Service Execution (wmiexec/psexec)",
        "description": "Detects impacket/psexec-style lateral movement via remote services.",
        "tactic": "Lateral Movement",
        "technique": "T1021.002",
        "technique_name": "Remote Services: SMB/Windows Admin Shares",
        "severity": "CRITICAL",
        "confidence": 0.90,
        "data_source": "Windows Security / Sysmon",
        "references": ["https://attack.mitre.org/techniques/T1021/002/"],
        "sigma": {
            "detection": {
                "selection": {
                    "ParentImage|endswith": "\\\\services.exe",
                    "CommandLine|contains": ["cmd.exe /Q /c", "2>&1"],
                },
                "condition": "selection",
            },
        },
        "splunk": 'index=windows EventCode=4688 ParentImage="*\\\\services.exe" CommandLine="*cmd.exe /Q /c*"',
        "elastic": 'process.parent.name:"services.exe" AND process.command_line:"*cmd.exe /Q /c*"',
        "kql": 'DeviceProcessEvents | where InitiatingProcessFileName =~ "services.exe" and ProcessCommandLine has "cmd.exe /Q /c"',
    },
    {
        "id": "R-0006",
        "title": "Suspicious Office Child Process (macro malware)",
        "description": "Office applications spawning cmd/powershell/wscript are a strong malicious macro signal.",
        "tactic": "Execution",
        "technique": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "severity": "HIGH",
        "confidence": 0.90,
        "data_source": "Windows Process Creation",
        "references": ["https://attack.mitre.org/techniques/T1059/"],
        "sigma": {
            "detection": {
                "selection_parent": {"ParentImage|endswith": ["\\\\WINWORD.EXE", "\\\\EXCEL.EXE", "\\\\POWERPNT.EXE"]},
                "selection_child": {"Image|endswith": ["\\\\cmd.exe", "\\\\powershell.exe", "\\\\wscript.exe", "\\\\cscript.exe"]},
                "condition": "selection_parent and selection_child",
            },
        },
        "splunk": 'index=windows EventCode=4688 ParentImage IN ("*\\\\WINWORD.EXE","*\\\\EXCEL.EXE","*\\\\POWERPNT.EXE") Image IN ("*\\\\cmd.exe","*\\\\powershell.exe","*\\\\wscript.exe","*\\\\cscript.exe")',
        "elastic": 'process.parent.name:("winword.exe" OR "excel.exe" OR "powerpnt.exe") AND process.name:("cmd.exe" OR "powershell.exe" OR "wscript.exe" OR "cscript.exe")',
        "kql": 'DeviceProcessEvents | where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe") and FileName in~ ("cmd.exe","powershell.exe","wscript.exe","cscript.exe")',
    },
    {
        "id": "R-0007",
        "title": "AWS Root Account Usage",
        "description": "Root account should not be used for day-to-day operations.",
        "tactic": "Privilege Escalation",
        "technique": "T1078.004",
        "technique_name": "Valid Accounts: Cloud Accounts",
        "severity": "HIGH",
        "confidence": 0.95,
        "data_source": "AWS CloudTrail",
        "references": ["https://attack.mitre.org/techniques/T1078/004/"],
        "sigma": {
            "detection": {
                "selection": {"userIdentity.type": "Root", "eventType|neq": "AwsServiceEvent"},
                "condition": "selection",
            },
        },
        "splunk": 'sourcetype=aws:cloudtrail userIdentity.type=Root eventType!=AwsServiceEvent',
        "elastic": 'event.provider:"aws.cloudtrail" AND aws.cloudtrail.user_identity.type:"Root" AND NOT aws.cloudtrail.event_type:"AwsServiceEvent"',
        "kql": 'AWSCloudTrail | where userIdentityType == "Root" and eventType != "AwsServiceEvent"',
    },
    {
        "id": "R-0008",
        "title": "Disable Windows Defender via Registry",
        "description": "Attackers disable Defender by setting DisableAntiSpyware=1 in HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender.",
        "tactic": "Defense Evasion",
        "technique": "T1562.001",
        "technique_name": "Impair Defenses: Disable or Modify Tools",
        "severity": "HIGH",
        "confidence": 0.92,
        "data_source": "Sysmon EID 13 (RegistryValueSet)",
        "references": ["https://attack.mitre.org/techniques/T1562/001/"],
        "sigma": {
            "detection": {
                "selection": {
                    "EventID": 13,
                    "TargetObject|contains": "\\\\Policies\\\\Microsoft\\\\Windows Defender\\\\",
                    "Details": "DWORD (0x00000001)",
                },
                "condition": "selection",
            },
        },
        "splunk": 'sourcetype=sysmon EventCode=13 TargetObject="*\\\\Windows Defender\\\\*" Details="DWORD (0x00000001)"',
        "elastic": 'event.code:"13" AND winlog.event_data.TargetObject:"*Windows Defender*" AND winlog.event_data.Details:"DWORD (0x00000001)"',
        "kql": 'DeviceRegistryEvents | where RegistryKey has "Windows Defender" and RegistryValueData == "1"',
    },
    {
        "id": "R-0009",
        "title": "Suspicious DNS Tunneling Query Size",
        "description": "Unusually long DNS subdomain queries are a strong tunneling indicator (Cobalt Strike, DNScat, etc.).",
        "tactic": "Command and Control",
        "technique": "T1071.004",
        "technique_name": "Application Layer Protocol: DNS",
        "severity": "HIGH",
        "confidence": 0.80,
        "data_source": "DNS query logs",
        "references": ["https://attack.mitre.org/techniques/T1071/004/"],
        "sigma": {
            "detection": {
                "selection": {"query_length|gte": 80},
                "condition": "selection",
            },
        },
        "splunk": 'sourcetype=dns | where len(query) > 80',
        "elastic": 'dns.question.name.length:>80',
        "kql": 'DnsEvents | where strlen(Name) > 80',
    },
    {
        "id": "R-0010",
        "title": "Kubernetes Exec Into Privileged Pod",
        "description": "Detects kubectl exec into pods with privileged containers.",
        "tactic": "Execution",
        "technique": "T1610",
        "technique_name": "Deploy Container",
        "severity": "HIGH",
        "confidence": 0.85,
        "data_source": "Kubernetes audit log",
        "references": ["https://attack.mitre.org/techniques/T1610/"],
        "sigma": {
            "detection": {
                "selection": {"objectRef.subresource": "exec", "verb": "create"},
                "condition": "selection",
            },
        },
        "splunk": 'sourcetype=k8s:audit objectRef.subresource=exec verb=create',
        "elastic": 'kubernetes.audit.objectRef.subresource:"exec" AND kubernetes.audit.verb:"create"',
        "kql": 'KubeAudit | where ObjectRef contains "exec" and Verb == "create"',
    },
    {
        "id": "R-0011",
        "title": "Suspicious Base64-Encoded PowerShell Payload",
        "description": "Catches encoded payloads by base64 entropy + known marker strings.",
        "tactic": "Defense Evasion",
        "technique": "T1027",
        "technique_name": "Obfuscated Files or Information",
        "severity": "MEDIUM",
        "confidence": 0.75,
        "data_source": "Process creation / Sysmon EID 1",
        "references": ["https://attack.mitre.org/techniques/T1027/"],
        "sigma": {
            "detection": {
                "selection": {"CommandLine|re": "[A-Za-z0-9+/]{100,}={0,2}"},
                "condition": "selection",
            },
        },
        "splunk": 'index=windows EventCode=4688 | regex CommandLine="[A-Za-z0-9+/]{100,}={0,2}"',
        "elastic": 'process.command_line:/[A-Za-z0-9+\\/]{100,}={0,2}/',
        "kql": 'DeviceProcessEvents | where ProcessCommandLine matches regex @"[A-Za-z0-9+/]{100,}={0,2}"',
    },
    {
        "id": "R-0012",
        "title": "New User Added to Domain Admins",
        "description": "High-impact privilege escalation detection - membership change to Domain Admins group.",
        "tactic": "Privilege Escalation",
        "technique": "T1098",
        "technique_name": "Account Manipulation",
        "severity": "CRITICAL",
        "confidence": 0.99,
        "data_source": "Windows Security (4728, 4732, 4756)",
        "references": ["https://attack.mitre.org/techniques/T1098/"],
        "sigma": {
            "detection": {
                "selection": {
                    "EventID": [4728, 4732, 4756],
                    "TargetUserName": "Domain Admins",
                },
                "condition": "selection",
            },
        },
        "splunk": 'index=windows EventCode IN (4728,4732,4756) TargetUserName="Domain Admins"',
        "elastic": 'event.code:(4728 OR 4732 OR 4756) AND winlog.event_data.TargetUserName:"Domain Admins"',
        "kql": 'SecurityEvent | where EventID in (4728,4732,4756) and TargetUserName == "Domain Admins"',
    },
]


def _index():
    by_id = {r["id"]: r for r in RULES}
    by_tech = {}
    for r in RULES:
        by_tech.setdefault(r["technique"], []).append(r)
    return by_id, by_tech


def list_rules():
    print(f"{'ID':<8} {'TECHNIQUE':<12} {'TACTIC':<22} {'SEV':<8} TITLE")
    print("-" * 100)
    for r in sorted(RULES, key=lambda x: (x["technique"], x["id"])):
        print(f"{r['id']:<8} {r['technique']:<12} {r['tactic']:<22} {r['severity']:<8} {r['title']}")


def search(keyword: str):
    kw = keyword.lower()
    for r in RULES:
        hay = " ".join([r["title"], r["description"], r["tactic"], r["technique"], r["technique_name"]]).lower()
        if kw in hay:
            print(f"[{r['id']}] {r['title']} ({r['technique']} / {r['tactic']})")


def show(rule_id: str):
    by_id, _ = _index()
    r = by_id.get(rule_id) or next((x for x in RULES if x["technique"] == rule_id), None)
    if not r:
        print(f"[x] Rule or technique not found: {rule_id}", file=sys.stderr); sys.exit(1)
    print(f"\n{r['id']}  {r['title']}")
    print("-" * (len(r['title']) + 10))
    print(f"Tactic     : {r['tactic']}")
    print(f"Technique  : {r['technique']}  ({r['technique_name']})")
    print(f"Severity   : {r['severity']}    Confidence: {r['confidence']}")
    print(f"Data source: {r['data_source']}")
    print(f"\nDescription:\n  {r['description']}\n")
    print("--- Sigma ---")
    print(json.dumps(r["sigma"], indent=2))
    print("\n--- Splunk SPL ---")
    print(r["splunk"])
    print("\n--- Elastic (KQL/EQL) ---")
    print(r["elastic"])
    print("\n--- Microsoft Sentinel (KQL) ---")
    print(r["kql"])
    print("\nReferences:")
    for ref in r["references"]:
        print(f"  - {ref}")
    print()


def export(fmt: str, out_dir: str):
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    fmt = fmt.lower()
    if fmt not in ("sigma", "splunk", "elastic", "kql", "json"):
        print(f"[x] Unknown format {fmt}", file=sys.stderr); sys.exit(1)
    for r in RULES:
        if fmt == "sigma":
            doc = {
                "title": r["title"], "id": r["id"], "status": "stable",
                "description": r["description"],
                "references": r["references"],
                "tags": [f"attack.{r['technique'].lower()}", f"attack.{r['tactic'].lower().replace(' ', '_')}"],
                "level": r["severity"].lower(),
                **r["sigma"],
            }
            (Path(out_dir) / f"{r['id']}_{r['technique']}.yml").write_text(
                _to_yaml(doc), encoding="utf-8")
        elif fmt == "json":
            (Path(out_dir) / f"{r['id']}.json").write_text(json.dumps(r, indent=2), encoding="utf-8")
        else:
            (Path(out_dir) / f"{r['id']}.{fmt}.txt").write_text(r[fmt], encoding="utf-8")
    print(f"[+] Exported {len(RULES)} rules -> {out_dir} ({fmt})")


def _to_yaml(obj, indent=0):
    sp = "  " * indent
    if isinstance(obj, dict):
        out = []
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                out.append(f"{sp}{k}:")
                out.append(_to_yaml(v, indent + 1))
            else:
                out.append(f"{sp}{k}: {_yaml_scalar(v)}")
        return "\n".join(out)
    if isinstance(obj, list):
        return "\n".join(f"{sp}- {_yaml_scalar(x)}" if not isinstance(x, (dict, list))
                         else f"{sp}-\n{_to_yaml(x, indent + 1)}" for x in obj)
    return _yaml_scalar(obj)


def _yaml_scalar(v):
    if isinstance(v, str):
        if any(c in v for c in ":#{}[],&*!|>%@`") or v.strip() != v:
            return json.dumps(v)
        return v
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def coverage():
    """Print ATT&CK tactic x technique coverage table + generate HTML heatmap."""
    tactics = {}
    for r in RULES:
        tactics.setdefault(r["tactic"], []).append(r)
    print("\nMITRE ATT&CK Coverage")
    print("=" * 60)
    print(f"Total rules: {len(RULES)}")
    print(f"Tactics covered: {len(tactics)}")
    print(f"Techniques covered: {len({r['technique'] for r in RULES})}\n")
    for t in sorted(tactics):
        print(f"  {t:<22} {len(tactics[t])} rule(s)")
        for r in tactics[t]:
            print(f"    - {r['technique']:<10} {r['title']}")
    generate_coverage_html(RULES, "reports/mitre_coverage.html")
    print("\n[+] HTML coverage map: reports/mitre_coverage.html")


def simulate(target: str):
    """Run rules against a directory of JSONL/JSON event logs (toy simulation)."""
    path = Path(target)
    events = []
    if path.is_dir():
        for p in path.rglob("*"):
            if p.suffix in (".jsonl", ".json"):
                events.extend(_read_events(p))
    else:
        events = _read_events(path)
    hits = 0
    hits_by_rule = {}
    for e in events:
        for r in RULES:
            if _match(r, e):
                hits += 1
                hits_by_rule.setdefault(r["id"], 0)
                hits_by_rule[r["id"]] += 1
    print(f"[*] Events scanned: {len(events)}")
    print(f"[*] Total rule hits: {hits}")
    print("\nBy rule:")
    for rid, n in sorted(hits_by_rule.items(), key=lambda x: -x[1]):
        r = next(x for x in RULES if x["id"] == rid)
        print(f"  {rid}  x{n}  [{r['severity']}] {r['title']}")


def _read_events(p: Path):
    try:
        text = p.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            pass
    return out


def _match(rule: dict, e: dict) -> bool:
    """Ultra-simple matcher: evaluates the rule's `sigma.detection.selection*` maps.

    Only fires if at least one selection (or all selections, for *_parent+*_child)
    has all fields matched. Rules whose sigma detection has no plain-dict selection
    are skipped (they need a real Sigma engine).
    """
    det = rule.get("sigma", {}).get("detection", {})
    selections = {k: v for k, v in det.items() if k.startswith("selection") and isinstance(v, dict)}
    if not selections:
        return False
    for sel in selections.values():
        if not sel:
            return False
        for key, pattern in sel.items():
            field, _, op = key.partition("|")
            val = _get_field(e, field)
            if not _op_match(op, val, pattern):
                return False
    return True


def _get_field(e, path):
    cur = e
    for part in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


def _op_match(op, val, pattern):
    if val is None:
        return False
    if isinstance(pattern, list):
        return any(_op_match(op, val, p) for p in pattern)
    s = str(val)
    if op == "" or op == "equal":
        return s == pattern or val == pattern
    if op == "endswith":
        return s.endswith(str(pattern).replace("\\\\", "\\"))
    if op == "contains":
        return str(pattern).replace("\\\\", "\\") in s
    if op == "re":
        try:
            return re.search(pattern, s) is not None
        except re.error:
            return False
    if op == "gte":
        try:
            return float(val) >= float(pattern)
        except Exception:
            return False
    if op == "neq":
        return s != pattern
    return False


def main():
    ap = argparse.ArgumentParser(description="MITRE ATT&CK Detection Rules Library")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="list all rules")
    sp = sub.add_parser("search", help="search by keyword")
    sp.add_argument("keyword")
    sp = sub.add_parser("show", help="show a rule (by ID or technique)")
    sp.add_argument("rule_id")
    sp = sub.add_parser("export", help="export to sigma/splunk/elastic/kql/json")
    sp.add_argument("fmt")
    sp.add_argument("out_dir")
    sub.add_parser("coverage", help="print ATT&CK coverage + HTML heatmap")
    sp = sub.add_parser("simulate", help="run rules against JSONL event logs")
    sp.add_argument("target")

    args = ap.parse_args()
    if args.cmd == "list":
        list_rules()
    elif args.cmd == "search":
        search(args.keyword)
    elif args.cmd == "show":
        show(args.rule_id)
    elif args.cmd == "export":
        export(args.fmt, args.out_dir)
    elif args.cmd == "coverage":
        coverage()
    elif args.cmd == "simulate":
        simulate(args.target)


if __name__ == "__main__":
    try:
        from license_guard import verify_license
        verify_license()
    except Exception:
        pass
    main()
