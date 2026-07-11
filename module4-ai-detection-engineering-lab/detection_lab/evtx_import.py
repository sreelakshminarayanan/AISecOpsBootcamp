from __future__ import annotations

import hashlib
import xml.etree.ElementTree as ET
from pathlib import Path, PureWindowsPath
from typing import Any

from Evtx.Evtx import Evtx


NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def _event_data(root: ET.Element) -> dict[str, str]:
    values: dict[str, str] = {}
    for node in root.findall(".//e:EventData/e:Data", NS):
        name = node.attrib.get("Name")
        if name:
            values[name] = node.text or ""
    return values


def _system_text(root: ET.Element, path: str, default: str = "") -> str:
    node = root.find(path, NS)
    return node.text if node is not None and node.text else default


def _event_id(root: ET.Element) -> int:
    return int(_system_text(root, ".//e:System/e:EventID", "0"))


def _timestamp(root: ET.Element) -> str:
    node = root.find(".//e:System/e:TimeCreated", NS)
    return node.attrib.get("SystemTime", "") if node is not None else ""


def _host(root: ET.Element) -> str:
    return _system_text(root, ".//e:System/e:Computer", "UNKNOWN")


def _hashes(raw: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for part in raw.split(","):
        if "=" in part:
            name, value = part.split("=", 1)
            if name.strip().upper() == "SHA256":
                result["sha256"] = value.strip().lower()
    return result


def _base(root: ET.Element, data: dict[str, str], event_id: int, source_file: str, record_number: int) -> dict[str, Any]:
    guid = data.get("ProcessGuid") or data.get("SourceProcessGuid") or f"evtx-{record_number}"
    uid = hashlib.sha256(f"{source_file}:{record_number}:{guid}".encode()).hexdigest()[:32]
    user = data.get("User", "")
    domain, _, name = user.partition("\\")
    return {
        "@timestamp": _timestamp(root),
        "event": {"code": str(event_id), "provider": "Microsoft-Windows-Sysmon"},
        "host": {"name": _host(root), "os": {"type": "windows"}},
        "user": {"domain": domain, "name": name or domain},
        "winlog": {"event_id": event_id, "channel": "Microsoft-Windows-Sysmon/Operational", "provider_name": "Microsoft-Windows-Sysmon"},
        "labels": {"source_format": "evtx", "source_file": source_file},
        "lab": {"expected": False, "malicious": False, "scenario": "imported_evtx", "event_uid": uid},
    }


def map_sysmon_event(root: ET.Element, source_file: str, record_number: int) -> dict[str, Any] | None:
    event_id = _event_id(root)
    data = _event_data(root)
    event = _base(root, data, event_id, source_file, record_number)
    if event_id == 1:
        event["event"].update({"category": "process", "type": "start", "action": "process-created"})
        event["process"] = {
            "name": PureWindowsPath(data.get("Image", "")).name, "executable": data.get("Image", ""),
            "command_line": data.get("CommandLine", ""), "entity_id": data.get("ProcessGuid", ""),
            "pid": int(data.get("ProcessId", "0") or 0), "hash": _hashes(data.get("Hashes", "")),
            "parent": {"name": PureWindowsPath(data.get("ParentImage", "")).name, "executable": data.get("ParentImage", ""), "command_line": data.get("ParentCommandLine", ""), "entity_id": data.get("ParentProcessGuid", ""), "pid": int(data.get("ParentProcessId", "0") or 0)},
        }
    elif event_id == 3:
        event["event"].update({"category": "network", "type": "connection", "action": "network-connection"})
        event["process"] = {"name": PureWindowsPath(data.get("Image", "")).name, "executable": data.get("Image", ""), "entity_id": data.get("ProcessGuid", ""), "pid": int(data.get("ProcessId", "0") or 0)}
        event["source"] = {"ip": data.get("SourceIp", "0.0.0.0"), "port": int(data.get("SourcePort", "0") or 0)}
        event["destination"] = {"ip": data.get("DestinationIp", "0.0.0.0"), "port": int(data.get("DestinationPort", "0") or 0), "domain": data.get("DestinationHostname", "")}
        event["network"] = {"transport": data.get("Protocol", "").lower(), "direction": "egress"}
    elif event_id == 11:
        event["event"].update({"category": "file", "type": "creation", "action": "file-created"})
        event["process"] = {"name": PureWindowsPath(data.get("Image", "")).name, "executable": data.get("Image", ""), "entity_id": data.get("ProcessGuid", ""), "pid": int(data.get("ProcessId", "0") or 0)}
        event["file"] = {"path": data.get("TargetFilename", ""), "name": PureWindowsPath(data.get("TargetFilename", "")).name}
    elif event_id == 13:
        event["event"].update({"category": "registry", "type": "change", "action": "registry-value-set"})
        event["process"] = {"name": PureWindowsPath(data.get("Image", "")).name, "executable": data.get("Image", ""), "entity_id": data.get("ProcessGuid", ""), "pid": int(data.get("ProcessId", "0") or 0)}
        event["registry"] = {"path": data.get("TargetObject", ""), "data": data.get("Details", "")}
    else:
        return None
    return event


def import_evtx(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with Evtx(str(path)) as log:
        for record in log.records():
            try:
                root = ET.fromstring(record.xml())
                mapped = map_sysmon_event(root, path.name, record.record_num())
                if mapped:
                    events.append(mapped)
            except (ET.ParseError, ValueError):
                continue
    return events
