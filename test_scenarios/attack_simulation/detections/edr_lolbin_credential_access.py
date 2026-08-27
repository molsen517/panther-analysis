"""
EDR: LOLBin Abuse and Credential Access
SentinelOne DeepVisibilityV2

Detects:
  - Known LOLBins used in pre-ransomware intrusions
  - PowerShell with obfuscation flags (-enc, -nop, -w hidden)
  - Cross-process access to lsass.exe (credential dumping)

ATT&CK: T1059.001, T1003.001, T1218
"""

import re
from panther_base_helpers import deep_get

LOLBINS = {
    "certutil.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe",
    "wscript.exe", "cscript.exe", "bitsadmin.exe", "msiexec.exe",
    "installutil.exe", "msbuild.exe", "cmstp.exe", "ieexec.exe",
}

PS_SUSPICIOUS_FLAGS = re.compile(
    r"(-enc|-encodedcommand|-nop|-noprofile|-w\s+hidden|-windowstyle\s+hidden)",
    re.IGNORECASE,
)


def _get_proc(event, field: str) -> str:
    """Read flat dot-notation S1 field with path stripping."""
    val = event.get(field) or ""
    return val.lower().split("\\")[-1].split("/")[-1]


def rule(event) -> bool:
    src_name = _get_proc(event, "src.process.name")
    src_cmd  = event.get("src.process.cmdline") or ""
    tgt_name = _get_proc(event, "tgt.process.name")

    if src_name in LOLBINS:
        return True
    if src_name == "powershell.exe" and PS_SUSPICIOUS_FLAGS.search(src_cmd):
        return True
    if tgt_name == "lsass.exe":
        return True
    return False


def title(event) -> str:
    proc = event.get("src.process.name") or "unknown"
    host = event.get("endpoint.name") or "unknown-host"
    tgt  = event.get("tgt.process.name") or ""
    if tgt.lower() == "lsass.exe":
        return f"[EDR] LSASS credential access by {proc} on {host}"
    return f"[EDR] LOLBin/suspicious process: {proc} on {host}"


def alert_context(event) -> dict:
    return {
        "host":          event.get("endpoint.name"),
        "os":            event.get("endpoint.os"),
        "src_proc":      event.get("src.process.name"),
        "src_cmd":       event.get("src.process.cmdline"),
        "src_sha256":    event.get("src.process.image.sha256"),
        "src_parent":    event.get("src.process.parent.name"),
        "tgt_proc":      event.get("tgt.process.name"),
        "event_type":    event.get("event.type"),
        "event_category":event.get("event.category"),
    }


def dedup(event) -> str:
    host = event.get("endpoint.name") or "unknown"
    proc = event.get("src.process.name") or "unknown"
    return f"{host}:{proc}"
