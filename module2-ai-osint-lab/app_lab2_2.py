import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st


OUTPUT_DIR = Path("outputs")

ATTACK_CACHE_JSON = OUTPUT_DIR / "attack_enterprise_techniques.json"
ATTACK_CACHE_CSV = OUTPUT_DIR / "attack_enterprise_techniques.csv"
ATTACK_METADATA_JSON = OUTPUT_DIR / "attack_enterprise_metadata.json"

LATEST_IOCS_CSV = OUTPUT_DIR / "lab2_1_latest_iocs.csv"

LATEST_FINAL_MAPPING_CSV = OUTPUT_DIR / "lab2_2_latest_attack_mapping.csv"
LATEST_FINAL_MAPPING_JSON = OUTPUT_DIR / "lab2_2_latest_attack_mapping.json"
LATEST_REVIEW_MAPPING_CSV = OUTPUT_DIR / "lab2_2_latest_attack_mapping_review.csv"
LATEST_REJECTED_MAPPING_CSV = OUTPUT_DIR / "lab2_2_latest_attack_mapping_rejected.csv"

LATEST_NAVIGATOR_LAYER_JSON = OUTPUT_DIR / "lab2_2_latest_attack_navigator_layer.json"

LATEST_HUNTING_PACK_MD = OUTPUT_DIR / "lab2_2_latest_hunting_pack.md"
LATEST_HUNTING_PACK_JSON = OUTPUT_DIR / "lab2_2_latest_hunting_pack.json"


st.set_page_config(
    page_title="Lab 2.2 Dynamic ATT&CK Mapping Workbench",
    layout="wide",
)


def init_state() -> None:
    defaults = {
        "last_command": "",
        "last_stdout": "",
        "last_stderr": "",
        "last_returncode": None,
        "workflow_status": "Ready",
    }

    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def run_command(command: list[str], timeout: int = 600) -> bool:
    st.session_state["last_command"] = " ".join(command)
    st.session_state["last_stdout"] = ""
    st.session_state["last_stderr"] = ""
    st.session_state["last_returncode"] = None

    try:
        completed = subprocess.run(
            command,
            cwd=Path.cwd(),
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
    except subprocess.TimeoutExpired as exc:
        st.session_state["last_stdout"] = exc.stdout or ""
        st.session_state["last_stderr"] = exc.stderr or "Command timed out."
        st.session_state["last_returncode"] = 124
        st.session_state["workflow_status"] = "Failed"
        return False
    except Exception as exc:
        st.session_state["last_stderr"] = str(exc)
        st.session_state["last_returncode"] = 1
        st.session_state["workflow_status"] = "Failed"
        return False

    st.session_state["last_stdout"] = completed.stdout or ""
    st.session_state["last_stderr"] = completed.stderr or ""
    st.session_state["last_returncode"] = completed.returncode

    if completed.returncode == 0:
        st.session_state["workflow_status"] = "Success"
        return True

    st.session_state["workflow_status"] = "Failed"
    return False


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}

    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return {}


def read_text(path: Path) -> str:
    if not path.exists():
        return ""

    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def read_csv(path: Path) -> pd.DataFrame:
    if not path.exists():
        return pd.DataFrame()

    try:
        return pd.read_csv(path).fillna("")
    except Exception:
        return pd.DataFrame()


def newest_file(pattern: str) -> Path | None:
    matches = sorted(
        OUTPUT_DIR.glob(pattern),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )

    if not matches:
        return None

    return matches[0]


def path_status(path: Path) -> str:
    if path.exists():
        size_kb = path.stat().st_size / 1024
        return f"Available ({size_kb:.1f} KB)"

    return "Missing"


def file_download(label: str, path: Path, mime: str) -> None:
    if path.exists():
        st.download_button(
            label=label,
            data=path.read_bytes(),
            file_name=path.name,
            mime=mime,
        )
    else:
        st.button(label, disabled=True)


def show_command_output() -> None:
    with st.expander("Command output", expanded=False):
        st.write("Command:")
        st.code(st.session_state.get("last_command", "") or "No command executed yet.")

        returncode = st.session_state.get("last_returncode")

        if returncode is not None:
            st.write(f"Return code: `{returncode}`")

        stdout = st.session_state.get("last_stdout", "")
        stderr = st.session_state.get("last_stderr", "")

        if stdout:
            st.write("stdout:")
            st.code(stdout)

        if stderr:
            st.write("stderr:")
            st.code(stderr)


def show_attack_cache_panel() -> None:
    st.subheader("1. ATT&CK Dataset Cache")

    metadata = read_json(ATTACK_METADATA_JSON)

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("Technique cache", "Ready" if ATTACK_CACHE_JSON.exists() else "Missing")

    with col2:
        st.metric("Technique count", metadata.get("technique_count", "Unknown"))

    with col3:
        st.metric("Sub-techniques", metadata.get("subtechnique_count", "Unknown"))

    if metadata:
        with st.expander("ATT&CK cache metadata", expanded=False):
            st.json(metadata)

    st.write(f"JSON cache: `{ATTACK_CACHE_JSON}` - {path_status(ATTACK_CACHE_JSON)}")
    st.write(f"CSV cache: `{ATTACK_CACHE_CSV}` - {path_status(ATTACK_CACHE_CSV)}")

    if st.button("Sync latest Enterprise ATT&CK dataset", type="primary"):
        with st.spinner("Downloading and parsing current Enterprise ATT&CK dataset..."):
            ok = run_command(
                [
                    sys.executable,
                    "tools/attack_dataset_sync.py",
                ],
                timeout=600,
            )

        if ok:
            st.success("ATT&CK dataset sync completed.")
        else:
            st.error("ATT&CK dataset sync failed. Check command output below.")


def show_lab2_1_inputs_panel() -> None:
    st.subheader("2. Lab 2.1 Inputs")

    evidence_file = newest_file("lab2_1_report_osint_*.json")
    easy_summary_file = newest_file("lab2_1_easy_summary_*.md")
    analyst_brief_file = newest_file("lab2_1_ai_brief_*.md")

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Evidence JSON", "Found" if evidence_file else "Missing")

    with col2:
        st.metric("Latest IOC CSV", "Found" if LATEST_IOCS_CSV.exists() else "Missing")

    with col3:
        st.metric("Easy Summary", "Found" if easy_summary_file else "Missing")

    with col4:
        st.metric("Analyst Brief", "Found" if analyst_brief_file else "Missing")

    if evidence_file:
        st.write(f"Evidence JSON: `{evidence_file}`")

    st.write(f"IOC CSV: `{LATEST_IOCS_CSV}` - {path_status(LATEST_IOCS_CSV)}")

    if easy_summary_file:
        st.write(f"Easy Summary: `{easy_summary_file}`")

    if analyst_brief_file:
        st.write(f"Analyst Brief: `{analyst_brief_file}`")

    ioc_df = read_csv(LATEST_IOCS_CSV)

    if not ioc_df.empty:
        with st.expander("Preview Lab 2.1 IOCs", expanded=False):
            st.dataframe(ioc_df.head(200), use_container_width=True, hide_index=True)
    else:
        st.warning("Lab 2.1 IOC CSV is missing or empty. Run Lab 2.1 first.")


def show_mapping_panel(model: str, candidate_count: int) -> None:
    st.subheader("3. Generate ATT&CK Mappings")

    st.write(
        "This step asks the local LLM to propose ATT&CK mappings, validates every returned technique ID against the local ATT&CK cache, "
        "and separates high/medium confidence mappings from low-confidence review items."
    )

    col1, col2, col3 = st.columns(3)

    with col1:
        if st.button("Run ATT&CK Mapping", type="primary"):
            with st.spinner("Running evidence-to-ATT&CK mapping engine..."):
                ok = run_command(
                    [
                        sys.executable,
                        "tools/attack_mapping_engine.py",
                        "--model",
                        model,
                        "--candidate-count",
                        str(candidate_count),
                    ],
                    timeout=900,
                )

            if ok:
                st.success("ATT&CK mapping completed.")
            else:
                st.error("ATT&CK mapping failed. Check command output below.")

    with col2:
        if st.button("Run No-AI Validation"):
            with st.spinner("Running explicit ATT&CK ID validation only..."):
                ok = run_command(
                    [
                        sys.executable,
                        "tools/attack_mapping_engine.py",
                        "--no-ai",
                    ],
                    timeout=300,
                )

            if ok:
                st.success("No-AI validation completed.")
            else:
                st.error("No-AI validation failed. Check command output below.")

    with col3:
        st.write("Current output:")
        st.write(f"`{LATEST_FINAL_MAPPING_CSV}`")

    final_df = read_csv(LATEST_FINAL_MAPPING_CSV)
    review_df = read_csv(LATEST_REVIEW_MAPPING_CSV)
    rejected_df = read_csv(LATEST_REJECTED_MAPPING_CSV)

    tab_final, tab_review, tab_rejected = st.tabs(
        [
            "Final mappings",
            "Review mappings",
            "Rejected or uncertain",
        ]
    )

    with tab_final:
        if final_df.empty:
            st.info("No final mappings available yet.")
        else:
            st.dataframe(final_df, use_container_width=True, hide_index=True)

    with tab_review:
        if review_df.empty:
            st.info("No review mappings available yet.")
        else:
            st.dataframe(review_df, use_container_width=True, hide_index=True)

    with tab_rejected:
        if rejected_df.empty:
            st.info("No rejected mappings available yet.")
        else:
            st.dataframe(rejected_df, use_container_width=True, hide_index=True)


def show_navigator_panel() -> None:
    st.subheader("4. Generate ATT&CK Navigator Layer")

    st.write(
        "This step converts final ATT&CK mappings into an importable Navigator JSON layer. "
        "The generated JSON can be imported into ATT&CK Navigator."
    )

    if st.button("Generate Navigator Layer", type="primary"):
        with st.spinner("Generating ATT&CK Navigator layer JSON..."):
            ok = run_command(
                [
                    sys.executable,
                    "tools/attack_navigator_layer_generator.py",
                ],
                timeout=300,
            )

        if ok:
            st.success("Navigator layer generated.")
        else:
            st.error("Navigator layer generation failed. Check command output below.")

    layer = read_json(LATEST_NAVIGATOR_LAYER_JSON)

    col1, col2 = st.columns(2)

    with col1:
        st.metric("Navigator layer", "Ready" if LATEST_NAVIGATOR_LAYER_JSON.exists() else "Missing")

    with col2:
        technique_count = len(layer.get("techniques", [])) if layer else 0
        st.metric("Techniques in layer", technique_count)

    st.write(f"Layer file: `{LATEST_NAVIGATOR_LAYER_JSON}` - {path_status(LATEST_NAVIGATOR_LAYER_JSON)}")

    if layer:
        with st.expander("Preview Navigator layer JSON", expanded=False):
            st.json(layer)

    st.markdown("Open ATT&CK Navigator here: https://mitre-attack.github.io/attack-navigator/")


def show_hunting_pack_panel() -> None:
    st.subheader("5. Generate Hunting Pack")

    st.write(
        "This step creates a Markdown hunting pack containing final ATT&CK mappings, review mappings, IOCs, hunting questions, "
        "and starter Splunk SPL plus Microsoft Sentinel or Defender KQL queries."
    )

    if st.button("Generate Hunting Pack", type="primary"):
        with st.spinner("Generating hunting pack..."):
            ok = run_command(
                [
                    sys.executable,
                    "tools/hunting_pack_generator.py",
                ],
                timeout=300,
            )

        if ok:
            st.success("Hunting pack generated.")
        else:
            st.error("Hunting pack generation failed. Check command output below.")

    hunting_pack = read_text(LATEST_HUNTING_PACK_MD)

    col1, col2 = st.columns(2)

    with col1:
        st.metric("Hunting pack", "Ready" if LATEST_HUNTING_PACK_MD.exists() else "Missing")

    with col2:
        st.metric("Length", f"{len(hunting_pack):,} chars" if hunting_pack else "0 chars")

    st.write(f"Markdown: `{LATEST_HUNTING_PACK_MD}` - {path_status(LATEST_HUNTING_PACK_MD)}")
    st.write(f"JSON: `{LATEST_HUNTING_PACK_JSON}` - {path_status(LATEST_HUNTING_PACK_JSON)}")

    if hunting_pack:
        with st.expander("Preview latest hunting pack", expanded=False):
            st.markdown(hunting_pack[:25000])

            if len(hunting_pack) > 25000:
                st.info("Preview truncated in UI. Download the full Markdown file below.")


def show_downloads_panel() -> None:
    st.subheader("6. Download Artifacts")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown("### ATT&CK Mapping")
        file_download("Download Final Mapping CSV", LATEST_FINAL_MAPPING_CSV, "text/csv")
        file_download("Download Final Mapping JSON", LATEST_FINAL_MAPPING_JSON, "application/json")
        file_download("Download Review Mapping CSV", LATEST_REVIEW_MAPPING_CSV, "text/csv")
        file_download("Download Rejected Mapping CSV", LATEST_REJECTED_MAPPING_CSV, "text/csv")

    with col2:
        st.markdown("### Navigator")
        file_download("Download Navigator Layer JSON", LATEST_NAVIGATOR_LAYER_JSON, "application/json")
        file_download("Download ATT&CK Technique Cache CSV", ATTACK_CACHE_CSV, "text/csv")
        file_download("Download ATT&CK Technique Cache JSON", ATTACK_CACHE_JSON, "application/json")

    with col3:
        st.markdown("### Hunting Pack")
        file_download("Download Hunting Pack Markdown", LATEST_HUNTING_PACK_MD, "text/markdown")
        file_download("Download Hunting Pack JSON", LATEST_HUNTING_PACK_JSON, "application/json")
        file_download("Download Lab 2.1 IOC CSV", LATEST_IOCS_CSV, "text/csv")


def show_full_pipeline_panel(model: str, candidate_count: int) -> None:
    st.subheader("7. One-Click Pipeline")

    st.warning(
        "Use this after individual components have already been tested. "
    )

    if st.button("Run Full Lab 2.2 Pipeline"):
        steps = [
            (
                "Sync ATT&CK dataset",
                [
                    sys.executable,
                    "tools/attack_dataset_sync.py",
                ],
                600,
            ),
            (
                "Generate ATT&CK mappings",
                [
                    sys.executable,
                    "tools/attack_mapping_engine.py",
                    "--model",
                    model,
                    "--candidate-count",
                    str(candidate_count),
                ],
                900,
            ),
            (
                "Generate Navigator layer",
                [
                    sys.executable,
                    "tools/attack_navigator_layer_generator.py",
                ],
                300,
            ),
            (
                "Generate hunting pack",
                [
                    sys.executable,
                    "tools/hunting_pack_generator.py",
                ],
                300,
            ),
        ]

        progress = st.progress(0)
        status = st.empty()

        all_ok = True

        for index, (label, command, timeout) in enumerate(steps, start=1):
            status.write(f"Running: {label}")
            ok = run_command(command, timeout=timeout)
            progress.progress(index / len(steps))

            if not ok:
                st.error(f"Pipeline failed at step: {label}")
                all_ok = False
                break

        if all_ok:
            st.success("Full Lab 2.2 pipeline completed.")


def show_quality_gate_panel() -> None:
    st.subheader("8. Analyst Quality Gate")

    st.markdown(
        """
Use this checklist before presenting the output as a completed analyst artifact:

1. Does the final ATT&CK mapping actually match behavior described in the source report?
2. Are low-confidence mappings kept in the review bucket?
3. Does the Navigator layer show only final mappings?
4. Does the hunting pack clearly state that SPL and KQL are starter hunts, not production detections?
5. Are IOCs verified against the original report?
6. Are the queries tuned to the target SIEM field names before operational use?
7. Are false-positive assumptions documented?
"""
    )


init_state()

st.title("Lab 2.2: Dynamic ATT&CK Mapping and Hunting Pack Generator")

st.caption(
    "Convert Lab 2.1 threat report evidence into ATT&CK mappings, an ATT&CK Navigator layer, and a SOC hunting pack."
)

with st.sidebar:
    st.header("Lab 2.2 Controls")

    model = st.selectbox(
        "Local Ollama model",
        ["llama3.2:3b", "llama3.1:8b", "mistral:7b"],
        index=0,
    )

    candidate_count = st.slider(
        "ATT&CK candidate count",
        min_value=10,
        max_value=100,
        value=30,
        step=10,
        help="Lower values reduce noise for small local models. 30 is recommended for llama3.2:3b.",
    )

    st.divider()

    st.markdown("### Artifact status")
    st.write(f"ATT&CK cache: {path_status(ATTACK_CACHE_JSON)}")
    st.write(f"Lab 2.1 IOCs: {path_status(LATEST_IOCS_CSV)}")
    st.write(f"Final mapping: {path_status(LATEST_FINAL_MAPPING_CSV)}")
    st.write(f"Navigator layer: {path_status(LATEST_NAVIGATOR_LAYER_JSON)}")
    st.write(f"Hunting pack: {path_status(LATEST_HUNTING_PACK_MD)}")

    st.divider()

    st.markdown("### Current command status")
    st.write(st.session_state.get("workflow_status", "Ready"))

st.markdown(
    """
This UI is the final wrapper around the Lab 2.2 component pipeline.

Workflow:

```text
Lab 2.1 outputs
-> current ATT&CK cache
-> AI-assisted ATT&CK mapping
-> final/review/rejected mapping split
-> ATT&CK Navigator JSON
-> SOC hunting pack
```

Core rule:

```text
The LLM proposes mappings. The ATT&CK cache validates technique IDs. The analyst validates correctness.
```
"""
)

show_attack_cache_panel()
st.divider()

show_lab2_1_inputs_panel()
st.divider()

show_mapping_panel(model=model, candidate_count=candidate_count)
st.divider()

show_navigator_panel()
st.divider()

show_hunting_pack_panel()
st.divider()

show_downloads_panel()
st.divider()

show_full_pipeline_panel(model=model, candidate_count=candidate_count)
st.divider()

show_quality_gate_panel()
st.divider()

show_command_output()
