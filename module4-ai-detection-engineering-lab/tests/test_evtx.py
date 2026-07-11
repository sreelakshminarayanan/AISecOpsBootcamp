from __future__ import annotations

import xml.etree.ElementTree as ET

from detection_lab.evtx_import import map_sysmon_event


PROCESS_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID><TimeCreated SystemTime="2026-07-10T09:15:04Z"/><Computer>WS-FIN-023</Computer></System>
<EventData>
<Data Name="ProcessGuid">{11111111-1111-1111-1111-111111111111}</Data>
<Data Name="ProcessId">5388</Data>
<Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
<Data Name="CommandLine">powershell.exe -enc SQBuAHYAbwBrAGUALQ</Data>
<Data Name="ParentProcessGuid">{22222222-2222-2222-2222-222222222222}</Data>
<Data Name="ParentProcessId">4820</Data>
<Data Name="ParentImage">C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE</Data>
<Data Name="ParentCommandLine">WINWORD.EXE Q3.docm</Data>
<Data Name="User">NEXUS\\j.singh</Data>
<Data Name="Hashes">SHA256=abcdef</Data>
</EventData></Event>"""


def test_sysmon_process_mapping() -> None:
    event = map_sysmon_event(ET.fromstring(PROCESS_XML), "sample.evtx", 12)
    assert event is not None
    assert event["event"]["category"] == "process"
    assert event["process"]["name"] == "powershell.exe"
    assert event["process"]["parent"]["name"] == "WINWORD.EXE"
    assert event["user"]["name"] == "j.singh"
    assert event["process"]["hash"]["sha256"] == "abcdef"
