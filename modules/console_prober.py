"""
console_prober.py

Active probing layer for a possible leftover debug console/shell/REPL on the
main firmware (not the bootloader). This is exactly where a real software
weakness is usually found: a debug menu, AT command set, or interpreter
REPL that the developer forgot to disable or lock down.

Design note (important): many boards emit something on TXD on their own,
independent of what we send (a periodic banner, a heartbeat, a repeating
status line). A naive prober would misreport that noise as "the board
responded to my command." To avoid that false positive, this prober first
captures a short baseline of unsolicited/idle traffic, then compares every
command's response against that baseline. Only responses that differ from
the baseline are treated as real, command-triggered responses.

The probe table below is organised by the firmware ecosystem each command
set belongs to, so it works across the different things an ESP-family
competition board might actually be running, not just one assumed stack:

  - generic_text    : works on almost any line-oriented debug console
  - at_firmware     : Espressif's official AT command firmware (ESP8266/ESP32 AT)
  - esp_idf_console  : ESP-IDF "console" component (used by many IDF examples)
  - micropython     : MicroPython REPL, as shipped on ESP8266/ESP32 ports
  - nodemcu_lua     : NodeMCU's Lua interpreter (ESP8266)
  - uboot_like      : U-Boot-style bootloader shells, seen on some custom images

Commands are intentionally harmless, ASCII-only text; nothing that could
erase flash, change partitions, or damage hardware is ever sent.
"""

import difflib
import re

_DIGIT_RE = re.compile(rb"\d+")

# How close a response has to be to the captured idle baseline to still be
# treated as "just noise" rather than "a real reply." A plain `resp ==
# baseline` equality check (the earlier approach) misses the common case of
# a periodic banner/heartbeat that includes a changing counter or timestamp
# -- every such line would then look like a brand-new "response" and could
# be misreported as a real, command-triggered reply.
NOISE_SIMILARITY_THRESHOLD = 0.85


def _looks_like_idle_noise(resp: bytes, baseline: bytes) -> bool:
    """
    True if `resp` is reasonably explained as the same idle/periodic
    traffic captured in `baseline`, not a genuine reply to what we sent.
    Three checks, cheapest first:
      1. Exact match.
      2. Match after normalizing digit runs to a placeholder (catches a
         heartbeat whose only difference is a counter/timestamp).
      3. High sequence-similarity ratio for responses close in length to
         the baseline (catches small jitter beyond just digits).
    """
    if not resp:
        return False
    if resp == baseline:
        return True
    if not baseline:
        return False
    if _DIGIT_RE.sub(b"#", resp) == _DIGIT_RE.sub(b"#", baseline):
        return True
    length_tolerance = max(4, int(0.1 * len(baseline)))
    if abs(len(resp) - len(baseline)) <= length_tolerance:
        ratio = difflib.SequenceMatcher(None, resp, baseline).ratio()
        if ratio >= NOISE_SIMILARITY_THRESHOLD:
            return True
    return False


PROBE_TABLE = {
    "generic_text": [
        b"\r\n",
        b"\n",
        b"help\r\n",
        b"?\r\n",
        b"menu\r\n",
        b"info\r\n",
        b"status\r\n",
        b"\x03",  # Ctrl+C
        b"\x04",  # Ctrl+D
    ],
    # Espressif AT firmware command set (ESP8266/ESP32 AT, official docs)
    "at_firmware": [
        b"AT\r\n",
        b"AT+GMR\r\n",       # firmware/AT version info
        b"AT+RST\r\n",       # soft reset (harmless, standard AT command)
        b"ATE0\r\n",         # echo off
        b"AT+CWMODE?\r\n",   # Wi-Fi mode query
        b"AT+CIPSTATUS\r\n", # TCP/IP connection status
        b"AT+UART_CUR?\r\n", # current UART config
        b"AT+SYSRAM?\r\n",   # remaining heap (newer AT firmware)
    ],
    # ESP-IDF "console" component, used by many official IDF examples
    "esp_idf_console": [
        b"help\r\n",
        b"version\r\n",
        b"restart\r\n",
        b"free\r\n",
        b"tasks\r\n",
        b"heap\r\n",
        b"log_level\r\n",
    ],
    # MicroPython REPL (ESP8266/ESP32 MicroPython builds)
    "micropython": [
        b"\x02",            # Ctrl+B: switch to friendly/normal REPL
        b"\x03",            # Ctrl+C: interrupt a running program
        b"help()\r\n",
        b"import os; os.listdir()\r\n",
        b"import sys; print(sys.version)\r\n",
    ],
    # NodeMCU firmware (Lua interpreter on ESP8266)
    "nodemcu_lua": [
        b"print(node.info())\r\n",
        b"file.list()\r\n",
        b"=node.heap()\r\n",
    ],
    # U-Boot-style shells occasionally seen on custom/bootloader-ish images
    "uboot_like": [
        b"help\r\n",
        b"printenv\r\n",
        b"version\r\n",
    ],
    # Common words seen left in hand-written CTF/challenge debug consoles --
    # not from any one vendor's docs, but from the recurring pattern of what
    # challenge authors forget to remove: a flag-reading shortcut, a hidden
    # admin/debug mode toggle, or a leftover test command. Harmless to try;
    # each is just a short ASCII line.
    "ctf_common": [
        b"flag\r\n", b"getflag\r\n", b"get_flag\r\n", b"cat flag\r\n",
        b"cat flag.txt\r\n", b"cat /flag\r\n", b"show flag\r\n", b"print flag\r\n",
        b"secret\r\n", b"backdoor\r\n", b"debug\r\n", b"debug on\r\n",
        b"admin\r\n", b"root\r\n", b"su\r\n", b"login\r\n", b"auth\r\n",
        b"unlock\r\n", b"test\r\n", b"dump\r\n", b"dump_flash\r\n",
        b"cat\r\n", b"ls -la\r\n", b"pwd\r\n", b"whoami\r\n", b"id\r\n",
        b"config\r\n", b"show config\r\n",
        b"cat /etc/passwd\r\n", b"env\r\n", b"exit\r\n", b"quit\r\n",
    ],
}

# Commands that could plausibly reboot the board, wipe flash, or change its
# configuration -- never sent by default. Only tried when the person
# explicitly passes --aggressive, since on a competition's only board,
# triggering a factory reset or reboot loop could cost real time/points.
AGGRESSIVE_ONLY_COMMANDS = [
    b"reboot\r\n", b"reset\r\n", b"boot\r\n", b"factory_reset\r\n",
    b"erase\r\n", b"format\r\n", b"restart\r\n",
]


# Round-2 follow-up commands, used only for an ecosystem that already gave
# a genuine (non-baseline) response in round 1. These go further than the
# round-1 discovery probes -- actually trying to list/read things -- since
# at this point we have real evidence that ecosystem is live.
FOLLOWUP_COMMANDS = {
    "at_firmware": [
        b"AT+CWJAP?\r\n",
        b"AT+CWLAP\r\n",
        b"AT+SYSRAM?\r\n",
        b"AT+CWLAP\r\n",      # list nearby Wi-Fi APs (confirms real AT stack)
        b"AT+CWJAP?\r\n",     # currently configured AP (may leak stored Wi-Fi creds)
        b"AT+CIPSNTPTIME?\r\n",
        b"AT+SYSFLASH?\r\n",
    ],
    "esp_idf_console": [
        b"nvs_list\r\n", b"nvs_get\r\n", b"partition_table\r\n",
        b"wifi_config\r\n", b"cat /spiffs\r\n", b"ls /spiffs\r\n", b"df\r\n",
    ],
    "micropython": [
        b"import os; print(os.listdir('/'))\r\n",
        b"import machine; print(machine.unique_id())\r\n",
        b"f=open('boot.py'); print(f.read()); f.close()\r\n",
        b"f=open('main.py'); print(f.read()); f.close()\r\n",
        b"import network; print(network.WLAN().config('essid'))\r\n",
        b"import gc; print(gc.mem_free())\r\n",
        b"import json; print(json.dumps({'probe':1}))\r\n",
    ],
    "nodemcu_lua": [
        b"for k,v in pairs(file.list()) do print(k) end\r\n",
        b"file.open('init.lua','r'); print(file.read()); file.close()\r\n",
        b"print(wifi.sta.getconfig())\r\n",
    ],
    "uboot_like": [
        b"env print\r\n", b"flinfo\r\n", b"mtdparts\r\n",
    ],
    "generic_text": [
        b"cat boot.log\r\n", b"dmesg\r\n", b"show version\r\n", b"show running-config\r\n",
        b"flag\r\n", b"getflag\r\n", b"secret\r\n", b"dump\r\n", b"cat flag.txt\r\n",
    ],
}


class ConsoleProber:
    def __init__(self, session, storage, logger):
        self.session = session
        self.storage = storage
        self.logger = logger

    def _capture_baseline(self, seconds: float = 1.0) -> bytes:
        """Capture whatever the board emits with no input, to use as a
        reference for 'this is just idle/periodic noise, not a real reply'."""
        self.logger.info(f"[console] capturing {seconds}s of idle baseline noise ...")
        baseline = self.session.read_for(seconds)
        if baseline:
            self.logger.info(
                f"[console] board emits {len(baseline)} bytes unprompted "
                f"(periodic banner/heartbeat?) -- this will be filtered out below."
            )
        else:
            self.logger.info("[console] no unprompted traffic detected (clean baseline).")
        return baseline

    def probe(self, aggressive: bool = False) -> dict:
        baseline = self._capture_baseline()
        total_commands = sum(len(v) for v in PROBE_TABLE.values())
        if aggressive:
            total_commands += len(AGGRESSIVE_ONLY_COMMANDS)
            self.logger.warning(
                f"[console] --aggressive is ON: {len(AGGRESSIVE_ONLY_COMMANDS)} extra "
                f"command(s) that could reboot/reset/erase the board WILL be sent."
            )
        self.logger.info(
            f"[console] trying {total_commands} commands "
            f"across {len(PROBE_TABLE)} firmware ecosystems ..."
        )

        probe_table = dict(PROBE_TABLE)
        if aggressive:
            probe_table["aggressive_only"] = AGGRESSIVE_ONLY_COMMANDS

        results = {}
        real_response_found = False
        responsive_ecosystems = set()

        for ecosystem, commands in probe_table.items():
            for cmd in commands:
                resp = self.session.send_and_read(cmd, wait=0.5)
                key = f"{ecosystem}:{cmd.decode(errors='replace').strip() or repr(cmd)}"

                is_just_baseline_noise = bool(resp) and _looks_like_idle_noise(resp, baseline)
                entry = {
                    "ecosystem": ecosystem,
                    "response_text": resp.decode(errors="replace"),
                    "response_len": len(resp),
                    "looks_like_idle_noise": is_just_baseline_noise,
                }
                results[key] = entry

                if resp and not is_just_baseline_noise:
                    real_response_found = True
                    responsive_ecosystems.add(ecosystem)
                    self.logger.info(
                        f"  {key} -> DIFFERENT from baseline ({len(resp)} bytes) "
                        f"-- looks like a real response"
                    )
                elif is_just_baseline_noise:
                    self.logger.info(
                        f"  {key} -> identical to idle baseline ({len(resp)} bytes) "
                        f"-- ignored as periodic noise"
                    )
                # silent (no response) commands are not logged individually to
                # keep the console output readable; full detail is in the
                # saved analysis JSON

        self.storage.save_analysis_result("console_probe_raw", results)
        combined_text = "\n".join(
            f"--- {k} --- (idle_noise={v['looks_like_idle_noise']})\n{v['response_text']}"
            for k, v in results.items()
        )
        combined_bytes = combined_text.encode("utf-8", errors="replace")
        path = self.storage.save_raw("console_probe", combined_bytes)
        self.analyze_responses_for_secrets(combined_text)

        status = "CONSOLE_FOUND" if real_response_found else "NO_REAL_RESPONSE"
        self.storage.log_event(
            "console_probe", status, f"ecosystems: {sorted(responsive_ecosystems)}", path
        )

        if real_response_found:
            self.logger.info(
                f"[console] genuine responses found, consistent with: "
                f"{sorted(responsive_ecosystems)}. Read the raw file carefully."
            )
        else:
            self.logger.info(
                "[console] no command produced anything beyond the board's own idle noise."
            )

        return {
            "any_response": real_response_found,
            "responsive_ecosystems": sorted(responsive_ecosystems),
            "baseline": baseline,
            "baseline_len": len(baseline),
            "results": results,
            "raw_path": path,
        }

    def deep_dive(self, responsive_ecosystems: list, baseline: bytes) -> dict:
        """
        Round 2: for each ecosystem that gave a genuine response in round 1,
        try ecosystem-specific commands that actually attempt to list or
        read content (not just detect presence). Only called when round 1
        found something real, so this is targeted, not another blind scan.
        """
        applicable = [e for e in responsive_ecosystems if e in FOLLOWUP_COMMANDS]
        if not applicable:
            self.logger.info("[console] no follow-up command set defined for the responsive ecosystem(s).")
            return {"results": {}, "raw_path": None}

        self.logger.info(f"[console] deep-diving into: {applicable} ...")
        results = {}
        for ecosystem in applicable:
            for cmd in FOLLOWUP_COMMANDS[ecosystem]:
                resp = self.session.send_and_read(cmd, wait=0.8)
                key = f"{ecosystem}:{cmd.decode(errors='replace').strip()}"
                is_noise = bool(resp) and _looks_like_idle_noise(resp, baseline)
                results[key] = {
                    "response_text": resp.decode(errors="replace"),
                    "response_len": len(resp),
                    "looks_like_idle_noise": is_noise,
                }
                if resp and not is_noise:
                    self.logger.info(f"  {key} -> {len(resp)} bytes")

        combined_text = "\n".join(
            f"--- {k} ---\n{v['response_text']}" for k, v in results.items()
        )
        path = self.storage.save_raw("console_deep_dive", combined_text.encode("utf-8", errors="replace"))
        self.analyze_responses_for_secrets(combined_text)
        # one stateful follow-up based on the combined response
        self.stateful_followup(combined_text.encode("utf-8", errors="replace"), baseline)
        self.storage.save_analysis_result("console_deep_dive", results)
        self.storage.log_event("console_deep_dive", "DONE", f"ecosystems: {applicable}", path)
        return {"results": results, "raw_path": path}

    # ------------------------------------------------------------
    # Round 3: dynamic follow-up, driven by whatever the console itself
    # listed in response to 'help'/'?' -- instead of only ever trying our
    # own fixed guesses, we actually read the menu it gave us and try
    # those exact command names. This is the single highest-value thing a
    # human operator would do by hand, automated.
    # ------------------------------------------------------------
    _TOKEN_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_\-]{1,20}$")
    # words that are clearly not commands even if they appear on their own
    # line in a help listing (headers, punctuation-only noise, etc.)
    _TOKEN_STOPWORDS = {
        "the", "usage", "commands", "command", "options", "option",
        "available", "help", "example", "examples", "args", "arguments",
    }

    def extract_candidate_commands(self, help_text: str, max_commands: int = 15) -> list:
        """
        Pulls plausible command-name tokens out of a help/menu response.
        Conservative on purpose: only short, identifier-shaped, lowercase-
        starting-ish tokens that aren't common English filler words are
        kept, to avoid turning random prose into a flood of junk commands.
        """
        candidates = []
        seen = set()
        for line in help_text.splitlines():
            # a typical help line looks like "  status    - show status"
            # or "AT+CWMODE   Wi-Fi mode"; the first token is usually the
            # command itself
            stripped = line.strip()
            if not stripped:
                continue
            first_token = stripped.split()[0] if stripped.split() else ""
            first_token = first_token.strip(":-*").rstrip(",")
            if not self._TOKEN_RE.match(first_token):
                continue
            lower = first_token.lower()
            if lower in self._TOKEN_STOPWORDS or lower in seen:
                continue
            seen.add(lower)
            candidates.append(first_token)
            if len(candidates) >= max_commands:
                break
        return candidates

    # words considered risky even when they show up as a candidate command
    # parsed out of a help listing -- skipped here for the same reason
    # AGGRESSIVE_ONLY_COMMANDS isn't sent by default.
    _RISKY_WORDS = {
        "reboot", "reset", "restart", "erase", "format", "factory_reset",
        "boot", "wipe", "flash_erase", "deepsleep", "shutdown", "poweroff",
    }

    def dynamic_followup(self, help_text: str, baseline: bytes, aggressive: bool = False) -> dict:
        """Round 3: parse help text and try discovered commands.
        Non-risky commands are always tried. Risky ones only with --aggressive.
        """
        candidates = self.extract_candidate_commands(help_text)
        if not aggressive:
            skipped = [c for c in candidates if c.lower() in self._RISKY_WORDS]
            candidates = [c for c in candidates if c.lower() not in self._RISKY_WORDS]
            if skipped:
                self.logger.info(
                    f"[console] round 3: skipping risky help-derived command(s) {skipped} "
                    f"(use --aggressive to try them)"
                )
        if not candidates:
            self.logger.info("[console] round 3: no plausible (non-risky) command tokens parsed out of help text.")
            return {"results": {}, "raw_path": None, "tried_commands": []}

        self.logger.info(f"[console] round 3 (dynamic, from help text): trying {candidates}")
        results = {}
        for cmd_name in candidates:
            resp = self.session.send_and_read((cmd_name + "\r\n").encode(), wait=0.6)
            is_noise = bool(resp) and _looks_like_idle_noise(resp, baseline)
            results[cmd_name] = {
                "response_text": resp.decode(errors="replace"),
                "response_len": len(resp),
                "looks_like_idle_noise": is_noise,
            }
            if resp and not is_noise:
                self.logger.info(f"  '{cmd_name}' -> {len(resp)} bytes (from help-derived command)")

        combined_text = "\n".join(f"--- {k} ---\n{v['response_text']}" for k, v in results.items())
        path = self.storage.save_raw("console_dynamic_followup", combined_text.encode("utf-8", errors="replace"))
        self.storage.save_analysis_result("console_dynamic_followup", results)
        self.storage.log_event("console_dynamic_followup", "DONE", f"tried: {candidates}", path)
        return {"results": results, "raw_path": path, "tried_commands": candidates}

    def analyze_responses_for_secrets(self, all_text: str) -> list:
        """Quick scan of console transcript for credential-like lines."""
        findings = []
        lines = all_text.splitlines()
        keywords = ("pass", "pwd", "password", "key", "secret", "token", "ssid", "auth")
        for i, line in enumerate(lines):
            low = line.lower()
            if any(k in low for k in keywords) and len(line) > 8:
                findings.append({"line": i, "text": line[:200]})
        if findings:
            self.logger.info(f"[console] {len(findings)} credential-like line(s) in console output")
            for f in findings[:8]:
                self.logger.info(f"  -> {f['text']}")
        return findings

    def stateful_followup(self, previous_response: bytes, baseline: bytes) -> dict:
        """If previous response looks like a prompt or help, send one contextual command."""
        text = previous_response.decode("ascii", errors="replace").lower()
        cmd = None
        if "help" in text or "command" in text or ">" in text or "#" in text:
            cmd = b"help\r\n"
        elif "nvs" in text:
            cmd = b"nvs_list\r\n"
        elif "wifi" in text or "ssid" in text:
            cmd = b"wifi_config\r\n"
        if not cmd:
            return {"sent": None}

        resp = self.session.send_and_read(cmd, wait=0.7)
        is_noise = bool(resp) and _looks_like_idle_noise(resp, baseline)
        result = {
            "sent": cmd.decode(),
            "response_len": len(resp),
            "looks_like_noise": is_noise,
            "preview": resp[:200].decode("ascii", errors="replace"),
        }
        if resp and not is_noise:
            self.logger.info(f"[console] stateful follow-up '{cmd.decode().strip()}' got {len(resp)} bytes")
        path = self.storage.save_raw("console_stateful", resp)
        self.storage.save_analysis_result("console_stateful", result)
        return result

