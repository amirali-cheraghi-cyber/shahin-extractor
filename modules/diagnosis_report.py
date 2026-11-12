"""
diagnosis_report.py

This module always produces exactly one clear, final verdict for the
session, regardless of how it went:

  - EXTRACTED: content was pulled off the board; here is the single file
  - BLOCKED_WITH_FINDINGS: extraction failed, but here is the specific,
    pinpointed weakness (or set of weaknesses) found, and what it implies
  - BLOCKED_NO_FINDINGS: extraction failed and nothing exploitable was
    identified by the checks this tool runs
  - CLEAN: the board was reachable and nothing restricted access at all
    (own test boards with no protection fall here, not "blocked")

This is the single place that turns everything the other modules collected
(security matrix, correlation findings, wiring check, console probe,
bootloader reachability) into one unambiguous answer, instead of leaving
the person to piece it together from scattered log lines.
"""

import os


class DiagnosisReport:
    def __init__(self, storage, logger):
        self.storage = storage
        self.logger = logger

    def build_and_print(
        self,
        chip_info: dict,
        bootloader_ok: bool,
        used_no_stub: bool,
        security_report: dict,
        wiring_result: dict,
        console_result: dict,
        extraction_path: str,
        dumped_files: list = None,
        correlation_report: dict = None,
    ) -> dict:
        verdict, headline = self._determine_verdict(
            bootloader_ok, security_report, extraction_path
        )

        is_ciphertext = bool(
            extraction_path
            and security_report
            and security_report.get("feature_status", {}).get("flash_encryption") == "ON"
        )

        report = {
            "verdict": verdict,
            "headline": headline,
            "chip": chip_info.get("chip") if chip_info else None,
            "chip_id_hex": chip_info.get("chip_id_hex") if chip_info else None,
            "bootloader_reachable": bootloader_ok,
            "used_no_stub_fallback": used_no_stub,
            "security_feature_status": security_report.get("feature_status", {}) if security_report else {},
            "weakness_findings": security_report.get("weakness_findings", []) if security_report else [],
            "wiring_self_loopback_detected": wiring_result.get("pattern_echoed_back", False) if wiring_result else None,
            "console_responsive_ecosystems": console_result.get("responsive_ecosystems", []) if console_result else [],
            "extraction_path": extraction_path or None,
            "extraction_is_ciphertext": is_ciphertext,
            "files_for_manual_review": self._build_manual_review_list(dumped_files or [], is_ciphertext),
            "correlation_assessment": (correlation_report or {}).get("assessment"),
            "ranked_findings": (correlation_report or {}).get("ranked_findings", []),
        }

        self._print(report)
        self.storage.save_analysis_result("diagnosis_report", report)
        self.storage.log_event("diagnosis", verdict, headline)
        return report

    @staticmethod
    def _build_manual_review_list(dumped_files: list, is_ciphertext: bool) -> list:
        """
        A short, reasoned list of which saved files are actually worth a
        person's time, and what to do with each -- so the team doesn't
        have to guess which of possibly a dozen files matters, or which
        tool to reach for.
        """
        entries = []
        for label, path in dumped_files:
            if "full_flash_dump" in label:
                hint = (
                    "this is ciphertext (Flash Encryption is ON) -- not directly "
                    "readable; needs the AES key to decrypt before inspecting"
                    if is_ciphertext else
                    "run `strings -n 8 <file>` for readable text, or `xxd <file> | less` "
                    "for a hex view; binwalk findings (if any) are in the static_* analysis file"
                )
            elif "partition_" in label:
                hint = "a single named partition; inspect with the tool matching its subtype (nvs/spiffs/littlefs/app)"
            elif "unpacked_" in label:
                hint = "an individually extracted file from a filesystem image -- read it directly"
            elif "console" in label:
                hint = "saved console session transcript; read for anything a human would recognise as meaningful"
            elif "boot_log" in label:
                hint = "captured boot-time output; scan for credentials, firmware version, stack traces"
            else:
                hint = "inspect with `strings -n 8` or `xxd` as a starting point"
            entries.append({"label": label, "path": path, "suggested_action": hint})
        return entries

    @staticmethod
    def _is_real_finding(finding) -> bool:
        """Accept the current structured finding schema and the legacy string schema."""
        if isinstance(finding, dict):
            return bool(finding.get("title") or finding.get("detail"))
        if isinstance(finding, str):
            return not finding.lower().startswith("no known misconfiguration")
        return bool(finding)

    @staticmethod
    def _finding_text(finding) -> str:
        """Render either a structured finding or a legacy string for human output."""
        if isinstance(finding, dict):
            severity = finding.get("severity", "INFO")
            title = finding.get("title", "Untitled finding")
            detail = finding.get("detail", "")
            confidence = finding.get("confidence")
            suffix = f" [confidence={confidence:.0%}]" if isinstance(confidence, (int, float)) else ""
            return f"[{severity}] {title}: {detail}{suffix}"
        return str(finding)

    @staticmethod
    def _determine_verdict(bootloader_ok, security_report, extraction_path):
        if not isinstance(security_report, dict):
            security_report = {}
        findings = security_report.get("weakness_findings") or []
        if not isinstance(findings, list):
            findings = []
        if extraction_path:
            return "EXTRACTED", f"content successfully extracted to {extraction_path}"

        real_findings = [f for f in findings if DiagnosisReport._is_real_finding(f)]
        if real_findings:
            return (
                "BLOCKED_WITH_FINDINGS",
                f"{len(real_findings)} specific weakness(es) identified; "
                f"see findings below for the exact mechanism and next step",
            )

        if not bootloader_ok:
            return (
                "BLOCKED_NO_FINDINGS",
                "bootloader unreachable and no known misconfiguration pattern matched; "
                "check console probe results and wiring by hand",
            )

        return (
            "BLOCKED_NO_FINDINGS",
            "bootloader reachable but extraction did not complete and no "
            "exploitable misconfiguration was identified by this tool's checks",
        )

    def _print(self, report: dict):
        self.logger.info("=" * 60)
        self.logger.info("DIAGNOSIS")
        self.logger.info("=" * 60)
        self.logger.info(f"verdict  : {report['verdict']}")
        self.logger.info(f"summary  : {report['headline']}")
        self.logger.info(f"chip     : {report['chip']} ({report['chip_id_hex']})")
        self.logger.info(
            f"bootloader reachable : {report['bootloader_reachable']}"
            + (" (via --no-stub fallback)" if report["used_no_stub_fallback"] else "")
        )
        if report["wiring_self_loopback_detected"]:
            self.logger.warning(
                "wiring   : WARNING -- self-loopback detected, results above may be unreliable"
            )
        if report["console_responsive_ecosystems"]:
            self.logger.info(
                f"console  : responsive ecosystem(s): {report['console_responsive_ecosystems']}"
            )
        if report["verdict"] == "BLOCKED_WITH_FINDINGS":
            self.logger.info("pinpointed weakness(es):")
            for f in report["weakness_findings"]:
                if self._is_real_finding(f):
                    self.logger.info(f"  -> {self._finding_text(f)}")

        if report["extraction_is_ciphertext"]:
            self.logger.warning(
                "NOTE: the extracted dump is ciphertext (Flash Encryption is ON). "
                "It is NOT directly usable without the AES key -- don't spend time "
                "reading it as plaintext."
            )

        if report["files_for_manual_review"]:
            self.logger.info("files worth a manual look:")
            for entry in report["files_for_manual_review"]:
                self.logger.info(f"  - {entry['label']}: {entry['path']}")
                self.logger.info(f"      -> {entry['suggested_action']}")

        # Write a clean human-readable summary.txt for the team
        self._write_summary_file(report)
        self.logger.info("=" * 60)

    def _write_summary_file(self, report: dict):
        """Writes a short, copy-paste friendly summary.txt in the session dir."""
        try:
            path = os.path.join(self.storage.session_dir, "summary.txt")
            lines = [
                "=== Shahin Extractor Diagnosis Summary ===",
                f"Verdict : {report.get('verdict', 'UNKNOWN')}",
                f"Summary : {report.get('headline', '')}",
                f"Chip    : {report.get('chip', 'unknown')} ({report.get('chip_id_hex', '')})",
                f"Bootloader reachable: {report.get('bootloader_reachable', False)}",
                "",
            ]
            if report.get("console_responsive_ecosystems"):
                lines.append(f"Console ecosystems: {report['console_responsive_ecosystems']}")
            if report.get("weakness_findings"):
                lines.append("")
                lines.append("Weakness findings:")
                for f in report["weakness_findings"]:
                    if self._is_real_finding(f):
                        lines.append(f"  - {self._finding_text(f)}")
            if report.get("ranked_findings"):
                lines.append("")
                lines.append(f"Correlation assessment: {report.get('correlation_assessment', 'UNKNOWN')}")
                lines.append("Top correlated findings:")
                for finding in report["ranked_findings"][:5]:
                    lines.append(
                        f"  - #{finding.get('rank', '?')} [{finding.get('category', 'unknown')}] "
                        f"{finding.get('title', 'Untitled')} "
                        f"(priority={finding.get('priority', '?')}, confidence={finding.get('confidence', '?')}%)"
                    )
            if report.get("files_for_manual_review"):
                lines.append("")
                lines.append("Priority files (auto-ranked):")
                for e in report["files_for_manual_review"]:
                    lines.append(f"  - {e.get('label')}: {e.get('path')}")
                    lines.append(f"    Suggested: {e.get('suggested_action', 'inspect with strings/xxd')}")
            lines.append("")
            lines.append("Automated extraction notes:")
            lines.append("=== AUTOMATED PRIORITY PATH ===")
            lines.append("1. Open correlation.json          → ranked_findings (start at rank 1)")
            lines.append("2. Open nvs_*.json                → NVS-like page strings")
            lines.append("3. Open deobf_*.json              → XOR / base64 recovered data")
            lines.append("4. Open binary_*.json             → candidate_configs + printable_islands")
            lines.append("5. Open auto_*.json               → json_credentials / env_credentials")
            lines.append("6. Open static_*.json             → high_value_strings + secrets")
            lines.append("7. If console responded          → console_deep_dive / dynamic_followup")
            lines.append("8. Last resort                    → manual strings/xxd")
            lines.append("")
            lines.append("The correlation engine already scored and ordered the signals.")
            lines.append("- If a console responded, check console_deep_dive and console_dynamic_followup raw files first.")
            lines.append("- Partition/filesystem carves (if any) are in the regions/ subfolder and have been re-analyzed.")
            if report.get("extraction_is_ciphertext"):
                lines.append("")
                lines.append("WARNING: Dump appears to be ciphertext (Flash Encryption ON).")
                lines.append("Do not treat it as plaintext. Focus on console logs and boot messages.")
            lines.append("")
            lines.append("All raw data is preserved in this session folder.")
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
            self.logger.info(f"[diagnosis] human summary written to {path}")
        except Exception as e:
            self.logger.warning(f"[diagnosis] could not write summary.txt: {e}")

