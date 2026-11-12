"""Chip-aware ESP security/eFuse audit.

The audit is intentionally read-only.  It uses Espressif's own ``espefuse
summary`` output and applies chip-specific semantics instead of generic
"contains 1" heuristics.  The knowledge base lives in ``boards/*.json`` so
new chips can be added without changing the parser.
"""

import json
import re
import subprocess
from pathlib import Path

DEFAULT_DB = Path(__file__).resolve().parent.parent / "boards"


def _load_board_db(db_dir=None):
    root = Path(db_dir or DEFAULT_DB)
    db = {}
    if root.exists():
        for path in sorted(root.glob("*.json")):
            try:
                item = json.loads(path.read_text(encoding="utf-8"))
                db[item["family"]] = item
            except Exception:
                continue
    return db


def _normalize_chip_family(chip_name: str) -> str:
    n = (chip_name or "").upper().replace(" ", "")
    # Longest/specific first.
    for family in ("ESP32-P4", "ESP32-H21", "ESP32-S31", "ESP32-C61", "ESP32-H4", "ESP32-C5", "ESP32-S3", "ESP32-S2", "ESP32-C6", "ESP32-C3", "ESP32-C2", "ESP32-H2", "ESP32", "ESP8266"):
        if family in n:
            return family
    return "UNKNOWN"


_FIELD_LINE_RE = re.compile(r"^([A-Z0-9_]+)\s*\([^)]*\).*?=\s*(.+?)\s+(R/W|R/-|-/W|-/-)\s+\(([^)]*)\)\s*$")
_GENERIC_KV_RE = re.compile(r"^([A-Za-z0-9_ \-]{2,48}?)\s*[:=]\s*(\S.*)$")


def parse_efuse_summary(raw: str) -> dict:
    """Parse both one-line fields and espefuse's two-line BLOCK_KEY entries."""
    fields = {}
    pending = None
    lines = raw.splitlines()
    for line in lines:
        text = line.strip()
        m = _FIELD_LINE_RE.match(text)
        if m:
            name, value, rw, raw_value = m.groups()
            fields[name] = {"value": value.strip(), "protection": rw, "raw_value": raw_value.strip(),
                            "readable": "-/W" not in rw and "-/-" not in rw,
                            "writeable": "R/-" not in rw and "-/-" not in rw}
            pending = None
            continue
        m2 = re.match(r"^([A-Z0-9_]+)\s*\(([^)]*)\)", text)
        if m2:
            pending = m2.group(1)
            continue
        if pending and text.startswith("="):
            pm = re.match(r"^=\s*(.*?)\s+(R/W|R/-|-/W|-/-)\s*(?:\(([^)]*)\))?$", text)
            if pm:
                value, rw, raw_value = pm.groups()
                fields[pending] = {"value": value.strip(), "protection": rw, "raw_value": (raw_value or "").strip(),
                                   "readable": "-/W" not in rw and "-/-" not in rw,
                                   "writeable": "R/-" not in rw and "-/-" not in rw}
                pending = None
    return fields


def parse_generic_keyvalue(raw: str) -> dict:
    out = {}
    for line in raw.splitlines():
        m = _GENERIC_KV_RE.match(line.strip())
        if m:
            key = m.group(1).strip().upper().replace(" ", "_").replace("-", "_")
            out[key] = {"value": m.group(2).strip(), "protection": None, "raw_value": None}
    return out


def _value_text(field):
    return str(field.get("value", field) if isinstance(field, dict) else field).strip().lower()


def _bool_value(field, inverted=False):
    v = _value_text(field)
    if v in {"true", "enabled", "enable", "yes", "on"}:
        result = True
    elif v in {"false", "disabled", "disable", "no", "off"}:
        result = False
    else:
        try:
            result = int(v, 0) != 0
        except ValueError:
            return None
    return not result if inverted else result


def _odd_bit_count(field):
    v = _value_text(field)
    if v in {"enable", "enabled", "on", "true"}:
        return True
    if v in {"disable", "disabled", "off", "false"}:
        return False
    try:
        # espefuse may render a bitfield as 0b..., decimal, or hex.
        return (int(v, 0).bit_count() % 2) == 1
    except ValueError:
        raw = field.get("raw_value", "") if isinstance(field, dict) else ""
        try:
            return (int(raw, 0).bit_count() % 2) == 1
        except (ValueError, TypeError):
            return None


def _uint_value(field):
    v = _value_text(field)
    try:
        return int(v, 0)
    except ValueError:
        raw = field.get("raw_value") if isinstance(field, dict) else None
        try:
            return int(raw, 0)
        except (ValueError, TypeError):
            return None


class SecurityAudit:
    def __init__(self, port, baud, storage, logger, chip_name="", board_db_dir=None):
        self.port = port
        self.baud = baud
        self.storage = storage
        self.logger = logger
        self.chip_name = chip_name or ""
        self.chip_family = _normalize_chip_family(chip_name)
        self.db = _load_board_db(board_db_dir)

    def _field(self, fields, names):
        for name in names:
            if name in fields:
                return name, fields[name]
        return None, None

    def _feature(self, name, spec, fields):
        if not spec.get("supported", True):
            return {"status": "N/A", "supported": False, "evidence": None}
        fname, field = self._field(fields, spec.get("fields", []))
        if field is None:
            return {"status": "UNKNOWN", "supported": True, "evidence": None}
        mode = spec.get("mode", "bool")
        if mode == "bool":
            state = _bool_value(field, inverted=spec.get("inverted", False))
        elif mode == "odd_bits":
            state = _odd_bit_count(field)
        elif mode == "positive_int":
            state = (_uint_value(field) or 0) > 0
        elif mode == "read_protected":
            state = field.get("readable") is False
        elif mode == "write_protected":
            state = field.get("writeable") is False
        else:
            state = None
        status = "UNKNOWN" if state is None else ("ON" if state else "OFF")
        return {
            "status": status,
            "supported": True,
            "field": fname,
            "value": field.get("value"),
            "raw_value": field.get("raw_value"),
            "protection": field.get("protection"),
            "readable": field.get("readable"),
            "writeable": field.get("writeable"),
            "evidence": f"{fname} = {field.get('value')} ({field.get('protection', '?')})",
        }

    def run(self, extra_raw_sources=None):
        cmd = ["espefuse", "--port", self.port, "--baud", str(self.baud), "summary"]
        raw = ""
        try:
            p = subprocess.run(cmd, capture_output=True, timeout=30, text=True)
            raw = (p.stdout or "") + "\n--STDERR--\n" + (p.stderr or "")
        except FileNotFoundError:
            self.logger.error("'espefuse' not found. Install esptool.")
        except subprocess.TimeoutExpired:
            self.logger.warning("[security] espefuse timed out")

        if raw:
            self.storage.save_text("efuse_summary", raw)
        fields = parse_efuse_summary(raw)
        sources = ["espefuse"] if fields else []

        for source_name, source_raw in (extra_raw_sources or []):
            for key, value in parse_generic_keyvalue(source_raw).items():
                if key not in fields:
                    fields[key] = value
                    if source_name not in sources:
                        sources.append(source_name)

        spec = self.db.get(self.chip_family, {})
        features = {}
        for name, feature_spec in spec.get("security_features", {}).items():
            features[name] = self._feature(name, feature_spec, fields)

        weaknesses = correlate_known_weaknesses(features)
        score = calculate_security_score(features, weaknesses)
        report = {
            "available": bool(fields),
            "chip": self.chip_name,
            "chip_family": self.chip_family,
            "board_db_loaded": bool(spec),
            "board_db_version": spec.get("version"),
            "sources_used": sources,
            "parsed_fields": fields,
            "features": features,
            "feature_status": {k: v["status"] for k, v in features.items()},
            "weakness_findings": weaknesses,
            "security_score": score,
            "note": spec.get("note", "Unknown chip family; do not infer support from absence of a field."),
        }
        self._print_feature_table(report)
        self.storage.save_analysis_result("security_audit", report)
        self.storage.log_event("security_audit", self.chip_family, str(report["feature_status"])[:500])
        return report

    def _print_feature_table(self, report):
        self.logger.info("------ security feature matrix ------")
        self.logger.info(f"chip: {report.get('chip') or '?'} | family: {report['chip_family']} | score: {report['security_score']['score']}/100")
        for name, item in report["features"].items():
            evidence = item.get("evidence") or ""
            self.logger.info(f"  {name:<30} {item['status']:<8} {evidence}")
        for finding in report["weakness_findings"]:
            self.logger.warning(f"  FINDING [{finding['severity']}]: {finding['title']} — {finding['detail']}")
        self.logger.info("-------------------------------------")


def correlate_known_weaknesses(features):
    if not isinstance(features, dict):
        return []
    def st(name):
        return features.get(name, {}).get("status")

    findings = []
    def add(severity, title, detail, evidence=None, confidence=0.9):
        findings.append({"severity": severity, "title": title, "detail": detail, "evidence": evidence or [], "confidence": confidence})

    if st("flash_encryption") == "OFF":
        add("HIGH", "Flash encryption is disabled", "A readable flash dump can expose firmware and stored plaintext data.", confidence=0.98)
    if st("secure_boot") == "OFF":
        add("HIGH", "Secure Boot is disabled", "Firmware authenticity is not enforced by the configured secure-boot fuse.", confidence=0.98)
    if st("uart_download_disable") == "OFF":
        add("HIGH", "UART download mode remains enabled", "ROM download commands remain reachable if the board can be placed in download mode.", confidence=0.95)
    if st("flash_encryption") == "ON" and st("download_dis_decrypt") == "OFF":
        add("CRITICAL", "Encrypted flash remains decryptable in UART download mode", "Flash encryption is active but UART decryption is not disabled; this can expose plaintext through the download path.", confidence=0.99)
    if st("flash_encryption") == "ON" and st("flash_key_read_protect") == "OFF":
        add("CRITICAL", "Flash-encryption key protection is incomplete", "The relevant key block does not report read protection; verify key-purpose mapping before treating this as a confirmed key disclosure.", confidence=0.85)
    if st("flash_encryption") == "ON" and st("flash_key_write_protect") == "OFF":
        add("HIGH", "Flash-encryption key block is not write-protected", "Key material may not be permanently locked against later programming; exact impact depends on chip generation and key-purpose mapping.", confidence=0.8)
    if st("secure_boot") == "ON" and st("flash_encryption") == "OFF":
        add("HIGH", "Secure Boot without flash confidentiality", "Signed firmware integrity does not prevent plaintext flash disclosure.", confidence=0.99)
    if st("secure_download_mode") == "ON" and st("uart_download_disable") == "OFF":
        add("INFO", "Secure download mode is enabled while download mode remains reachable", "Review the chip-specific secure-download semantics rather than treating download access alone as a bypass.", confidence=0.8)
    return findings


def calculate_security_score(features, weaknesses):
    weights = {
        "secure_boot": 25,
        "flash_encryption": 30,
        "uart_download_disable": 20,
        "download_dis_decrypt": 10,
        "flash_key_read_protect": 10,
        "flash_key_write_protect": 5,
    }
    earned = 0
    applicable = 0
    for name, weight in weights.items():
        st = features.get(name, {}).get("status")
        if st in ("ON", "OFF"):
            applicable += weight
            if st == "ON":
                earned += weight
    # Score is intentionally a posture score, not an exploit probability.
    # Each CRITICAL finding (e.g. flash encryption active but UART
    # decryption not disabled) additionally docks a flat 25 points, since
    # that combination is worse than the sum of its two individual feature
    # states would otherwise suggest.
    for finding in weaknesses:
        if finding["severity"] == "CRITICAL":
            earned = max(0, earned - 25)
    score = round((earned / applicable) * 100) if applicable else None
    return {"score": score, "applicable_weight": applicable, "note": "Posture score only; not a probability of compromise."}
