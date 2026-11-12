"""
Cross-module evidence correlation and ranked, non-destructive attack paths.

Loads every analysis module's output (security audit, console probe,
static secret scan, auto-extractor, NVS parser, deobfuscator) and ranks
them into one prioritized list of evidence paths.

STRONG is only declared when either one genuinely CRITICAL-severity
security finding exists, or at least two INDEPENDENT evidence categories
(e.g. security + credentials, or console + nvs) each clear a high bar --
real correlation across sources, not a single mid-tier finding.

Structured NVS hits (a fully decoded wifi_pass or mqtt_user key from
nvs_helper.py) are loaded and ranked as a "credentials" path, scored
higher than an unstructured string hit because they are a confirmed
key=value pair, not a guess.
"""

import json
import os


class CorrelationEngine:
    def __init__(self, storage, logger):
        self.storage = storage
        self.logger = logger

    def _load_all(self, prefix):
        found = []
        try:
            for root, _, files in os.walk(self.storage.session_dir):
                for fn in files:
                    if fn.startswith(prefix) and fn.endswith(".json"):
                        try:
                            with open(os.path.join(root, fn), encoding="utf-8") as f:
                                found.append(json.loads(f.read()))
                        except Exception:
                            pass
        except Exception:
            pass
        return found

    def correlate(self, security_report, dumped_files, console_result):
        if not isinstance(security_report, dict):
            security_report = {}
        if not isinstance(console_result, dict):
            console_result = {}

        weaknesses = security_report.get("weakness_findings", [])
        if not isinstance(weaknesses, list):
            weaknesses = []

        paths = []

        for finding in weaknesses:
            severity = finding.get("severity", "INFO")
            base = {"CRITICAL": 98, "HIGH": 90, "MEDIUM": 75, "INFO": 55}.get(severity, 50)
            paths.append({
                "priority": base,
                "confidence": round(finding.get("confidence", 0.8) * 100),
                "category": "security",
                "severity": severity,
                "title": finding["title"],
                "detail": finding["detail"],
                "evidence": finding.get("evidence", []),
                "next_action": "Validate the cited configuration and use only the corresponding read-only acquisition path.",
            })

        if console_result.get("responsive_ecosystems"):
            paths.append({
                "priority": 94, "confidence": 88, "category": "console",
                "title": "Responsive debug/command console",
                "detail": ", ".join(console_result["responsive_ecosystems"]),
                "next_action": "Review the saved console transcripts and read-only commands first.",
            })

        for item in self._load_all("static_"):
            count = len(item.get("secrets", []))
            if count:
                paths.append({
                    "priority": 92, "confidence": 84, "category": "credentials",
                    "title": f"{count} secret/config artifact(s) detected (static regex match)",
                    "detail": item.get("path", ""),
                    "next_action": "Review offsets and verify the finding in the original artifact.",
                })

        for item in self._load_all("auto_"):
            ext = item.get("extracted", {})
            count = len(ext.get("json_credentials", [])) + len(ext.get("env_credentials", []))
            if count:
                paths.append({
                    "priority": 93, "confidence": 86, "category": "credentials",
                    "title": f"{count} credential-like value(s) extracted",
                    "detail": item.get("path", ""),
                    "next_action": "Review auto extraction evidence and verify context.",
                })

        # NVS: structured hits are a *decoded, real* key=value pair from the
        # actual NVS format, so they're scored above an unstructured string
        # match; the old fallback scan (when a page didn't parse structurally)
        # stays scored low, same tier as the other heuristic scans.
        cred_keywords = ("pass", "pwd", "ssid", "wifi", "mqtt", "token", "secret", "key", "auth", "user")
        for item in self._load_all("nvs_"):
            structured = item.get("structured_items", [])
            sensitive = [it for it in structured if any(k in it.get("key", "").lower() for k in cred_keywords)]
            if sensitive:
                preview = ", ".join(f"{it['namespace']}/{it['key']}={it.get('value')!r}" for it in sensitive[:5])
                paths.append({
                    "priority": 95, "confidence": 92, "category": "credentials",
                    "title": f"{len(sensitive)} decoded NVS key-value pair(s) look sensitive",
                    "detail": preview, "evidence": [item.get("label", "")],
                    "next_action": "These are structurally decoded, real NVS entries -- verify the values directly.",
                })
            elif structured:
                paths.append({
                    "priority": 60, "confidence": 70, "category": "nvs",
                    "title": f"{len(structured)} decoded NVS key-value pair(s) (none look sensitive by name)",
                    "detail": item.get("label", ""),
                    "next_action": "Inspect the full key list; naming heuristics can miss relevant keys.",
                })
            fallback = item.get("fallback_strings", [])
            if fallback and not structured:
                paths.append({
                    "priority": 55, "confidence": 45, "category": "nvs",
                    "title": f"{len(fallback)} unstructured NVS-page string(s) (page did not parse structurally)",
                    "detail": item.get("label", ""),
                    "next_action": "Low confidence: page may be encrypted or corrupted. Treat as a lead, not a finding.",
                })

        for item in self._load_all("deobf_"):
            if item.get("interesting"):
                hits = (item.get("xor_candidates", []) + item.get("base64_layers", []))
                top_conf = max((h.get("confidence", 0) for h in hits), default=0)
                paths.append({
                    "priority": 85 if item.get("high_confidence") else 65,
                    "confidence": round(top_conf * 100),
                    "category": "obfuscation",
                    "title": "Decoding candidate found" + (" (high confidence)" if item.get("high_confidence") else ""),
                    "detail": item.get("path", ""),
                    "next_action": "Inspect the decoded preview; do not assume it is valid until context confirms it.",
                })

        paths.sort(key=lambda x: (-x["priority"], -x["confidence"]))
        for i, p in enumerate(paths, 1):
            p["rank"] = i

        categories_strong = {p["category"] for p in paths if p["priority"] >= 85}
        has_critical = any(p.get("severity") == "CRITICAL" for p in paths)
        if has_critical or len(categories_strong) >= 2:
            assessment = "STRONG"
        elif paths:
            assessment = "PARTIAL"
        else:
            assessment = "WEAK"

        report = {
            "assessment": assessment,
            "ranked_findings": paths,
            "priority_order": [p["title"] for p in paths],
            "security_posture_score": security_report.get("security_score"),
            "operator_notes": [
                "Correlation ranks evidence; it does not claim exploit success.",
                "Start with the highest-confidence read-only evidence.",
                "Unknown eFuse fields are never treated as OFF.",
                "STRONG now requires either one CRITICAL finding or >=2 independent evidence categories, not a single mid-tier finding.",
            ],
        }
        self.storage.save_analysis_result("correlation", report)
        return report
