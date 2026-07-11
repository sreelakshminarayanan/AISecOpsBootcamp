"""
AI SecOps Bootcamp - Module 2: Unified AI OSINT and ATT&CK Mapping Workbench.

A single Streamlit interface that runs the full workflow end to end:

    threat report URL
      -> passive fetch + IOC extraction + AI summaries        (Report to IOCs)
      -> current ATT&CK cache sync + AI-assisted mapping       (ATT&CK Mapping)
      -> ATT&CK Navigator layer                                (Navigator Layer)
      -> SOC hunting pack                                      (Hunting Pack)
      -> downloads + analyst quality gate                      (Deliverables)

Every AI step calls a real local Ollama model. The model is whatever you have
installed: the sidebar reads the installed models from Ollama directly, so no
model name is hardcoded. The LLM proposes; the local ATT&CK cache validates every
technique ID; the analyst decides.
"""
import json
from pathlib import Path

import pandas as pd
import streamlit as st
from bs4 import BeautifulSoup

from tools.ollama_client import ask_ollama, list_models, ollama_up
from tools.threat_report_ioc_extractor import (
    DEFAULT_USER_AGENT,
    build_ai_prompt,
    build_easy_summary_prompt,
    build_evidence,
    build_ioc_rows,
    build_rejected_rows,
    check_robots,
    extract_article_text,
    extract_iocs_from_text,
    extract_links,
    fetch_html,
    normalize_url,
    save_outputs,
)
from tools.attack_dataset_sync import sync_attack_dataset
from tools.attack_mapping_engine import run as run_attack_mapping
from tools.attack_navigator_layer_generator import run as run_navigator_layer
from tools.hunting_pack_generator import run as run_hunting_pack


OUTPUT_DIR = Path("outputs")

ATTACK_CACHE_JSON = OUTPUT_DIR / "attack_enterprise_techniques.json"
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
    page_title="Module 2 - AI OSINT and ATT&CK Workbench",
    layout="wide",
)


# --------------------------------------------------------------------------- #
# Small helpers                                                                #
# --------------------------------------------------------------------------- #
def read_csv(path: Path) -> pd.DataFrame:
    if not path.exists():
        return pd.DataFrame()
    try:
        return pd.read_csv(path).fillna("")
    except Exception:
        return pd.DataFrame()


def read_text(path: Path) -> str:
    if not path.exists():
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def path_status(path: Path) -> str:
    if path.exists():
        return f"Available ({path.stat().st_size / 1024:.1f} KB)"
    return "Missing"


def download_if_exists(label: str, path: Path, mime: str) -> None:
    if path.exists():
        st.download_button(label, data=path.read_bytes(), file_name=path.name, mime=mime)
    else:
        st.button(label, disabled=True)


def attack_cache_summary() -> dict:
    if not ATTACK_METADATA_JSON.exists():
        return {}
    try:
        return json.loads(ATTACK_METADATA_JSON.read_text(encoding="utf-8"))
    except Exception:
        return {}


# --------------------------------------------------------------------------- #
# Session state                                                                #
# --------------------------------------------------------------------------- #
for key, default in {
    "final_url": "",
    "easy_summary": "",
    "analyst_brief": "",
}.items():
    st.session_state.setdefault(key, default)


# --------------------------------------------------------------------------- #
# Sidebar: model discovery (model independent) + status                        #
# --------------------------------------------------------------------------- #
with st.sidebar:
    st.header("Model and status")

    ollama_online = ollama_up()
    installed_models = list_models() if ollama_online else []

    if not ollama_online:
        st.error("Ollama is not reachable. Start it with `ollama serve`.")
        selected_model = None
    elif not installed_models:
        st.warning("Ollama is running but no models are installed. Try `ollama pull llama3.1:8b`.")
        selected_model = None
    else:
        st.success(f"Ollama online. {len(installed_models)} model(s) installed.")
        selected_model = st.selectbox("Local Ollama model", installed_models, index=0)

    st.caption("The model list is read from your Ollama instance. Nothing is hardcoded.")

    st.divider()
    candidate_count = st.slider(
        "ATT&CK candidate count",
        min_value=10,
        max_value=100,
        value=40,
        step=10,
        help="Techniques scored and handed to the model for mapping. Lower values reduce noise for small models.",
    )

    st.divider()
    st.subheader("Passive fetch controls")
    respect_robots = st.checkbox("Respect robots.txt stop condition", value=True)
    user_agent = st.text_input("User-Agent", value=DEFAULT_USER_AGENT)

    st.divider()
    st.subheader("Artifact status")
    _meta = attack_cache_summary()
    st.write(f"ATT&CK cache: {path_status(ATTACK_CACHE_JSON)}")
    if _meta.get("attack_version"):
        st.write(f"ATT&CK version: {_meta.get('attack_version')}")
    st.write(f"Lab 2.1 IOCs: {path_status(LATEST_IOCS_CSV)}")
    st.write(f"Final mapping: {path_status(LATEST_FINAL_MAPPING_CSV)}")
    st.write(f"Navigator layer: {path_status(LATEST_NAVIGATOR_LAYER_JSON)}")
    st.write(f"Hunting pack: {path_status(LATEST_HUNTING_PACK_MD)}")


st.title("Module 2: AI OSINT and ATT&CK Mapping Workbench")
st.caption(
    "One interface for the whole flow: extract IOCs from a public threat report, map behavior to current "
    "ATT&CK, build a Navigator layer, and generate a SOC hunting pack. AI drafts, the ATT&CK cache validates, "
    "the analyst decides."
)

tab_report, tab_mapping, tab_navigator, tab_hunting, tab_deliverables = st.tabs(
    [
        "1. Report to IOCs",
        "2. ATT&CK Mapping",
        "3. Navigator Layer",
        "4. Hunting Pack",
        "5. Deliverables",
    ]
)


# --------------------------------------------------------------------------- #
# Tab 1: Report to IOCs                                                        #
# --------------------------------------------------------------------------- #
with tab_report:
    st.subheader("Extract validated IOCs and AI summaries from a public report")
    st.write(
        "Paste a public threat intel report URL. The app checks robots.txt, fetches the page passively, "
        "extracts article text, links, and validated IOCs, and asks the local model for an easy summary and an "
        "analyst brief. Use public or authorized sources only. No scanning, exploitation, or private content."
    )

    with st.form("report_form"):
        url = st.text_input("Threat report URL", placeholder="https://unit42.paloaltonetworks.com/...")
        gen_easy = st.checkbox("Generate easy summary", value=True)
        gen_brief = st.checkbox("Generate analyst brief", value=True)
        submitted = st.form_submit_button("Analyze report", type="primary")

    if submitted:
        try:
            if not url.strip():
                st.warning("Paste a report URL first.")
                st.stop()

            clean_url = normalize_url(url.strip())
            st.write(f"Source URL: {clean_url}")

            with st.spinner("Checking robots.txt..."):
                robots = check_robots(clean_url, user_agent)
            st.json(robots)

            if respect_robots and robots.get("allowed") is False:
                st.error("robots.txt disallows this fetch for the configured user agent. Stopping.")
                st.stop()

            with st.spinner("Fetching report page..."):
                fetched = fetch_html(clean_url, user_agent)

            st.json(
                {
                    "final_url": fetched["final_url"],
                    "status_code": fetched["status_code"],
                    "content_type": fetched["content_type"],
                }
            )

            if fetched["status_code"] >= 400 or not fetched.get("html"):
                st.error("Could not retrieve a usable HTML report page.")
                st.stop()

            soup = BeautifulSoup(fetched["html"], "lxml")

            with st.spinner("Parsing article text, links, and IOCs..."):
                article = extract_article_text(soup)
                links = extract_links(soup, fetched["final_url"])
                extraction_text = "\n".join(
                    [
                        article["title"],
                        article["meta"].get("description", ""),
                        article["meta"].get("og:description", ""),
                        article["article_text"],
                    ]
                )
                iocs = extract_iocs_from_text(extraction_text)

            evidence = build_evidence(
                url=clean_url, fetched=fetched, article=article, links=links, iocs=iocs, robots=robots
            )
            st.session_state["final_url"] = fetched["final_url"]

            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Article chars", evidence["article"]["article_text_length"])
            c2.metric("Links", evidence["link_count"])
            c3.metric("Accepted IOCs", evidence["accepted_ioc_count"])
            c4.metric("Rejected FPs", evidence["rejected_false_positive_count"])

            st.markdown("#### Validated IOCs")
            accepted_df = pd.DataFrame(build_ioc_rows(iocs))
            if accepted_df.empty:
                st.warning("No validated IOCs extracted from this page.")
            else:
                st.dataframe(accepted_df, use_container_width=True, hide_index=True)

            st.markdown("#### Rejected false positives")
            rejected_df = pd.DataFrame(build_rejected_rows(iocs))
            if rejected_df.empty:
                st.info("No rejected false positives recorded.")
            else:
                st.dataframe(rejected_df, use_container_width=True, hide_index=True)

            easy_summary = ""
            analyst_brief = ""

            if gen_easy or gen_brief:
                if not selected_model:
                    st.error("No usable Ollama model. Select one in the sidebar or install a model, then rerun.")
                else:
                    tab_easy, tab_brief = st.tabs(["Easy summary", "Analyst brief"])

                    if gen_easy:
                        with tab_easy:
                            with st.spinner(f"Generating easy summary with {selected_model}..."):
                                easy_summary = ask_ollama(
                                    build_easy_summary_prompt(fetched["final_url"], article, iocs, links),
                                    model=selected_model,
                                    temperature=0.2,
                                    num_predict=1200,
                                )
                            st.markdown(easy_summary)

                    if gen_brief:
                        with tab_brief:
                            with st.spinner(f"Generating analyst brief with {selected_model}..."):
                                analyst_brief = ask_ollama(
                                    build_ai_prompt(fetched["final_url"], article, iocs, links),
                                    model=selected_model,
                                    temperature=0.2,
                                    num_predict=1400,
                                )
                            st.markdown(analyst_brief)

            st.session_state["easy_summary"] = easy_summary
            st.session_state["analyst_brief"] = analyst_brief

            with st.spinner("Saving outputs for the mapping stage..."):
                paths = save_outputs(
                    source_url=fetched["final_url"],
                    evidence=evidence,
                    ai_brief=analyst_brief,
                    easy_summary=easy_summary,
                )

            st.success("Report analyzed and outputs saved. Move to the ATT&CK Mapping tab.")
            st.write(f"Evidence JSON: `{paths['json']}`")
            st.write(f"Latest IOC CSV: `{paths['latest_iocs']}`")

        except Exception as exc:
            st.error(f"Error: {exc}")


# --------------------------------------------------------------------------- #
# Tab 2: ATT&CK mapping                                                        #
# --------------------------------------------------------------------------- #
with tab_mapping:
    st.subheader("Sync current ATT&CK, then map report behavior to techniques")

    _meta = attack_cache_summary()
    c1, c2, c3 = st.columns(3)
    c1.metric("Technique cache", "Ready" if ATTACK_CACHE_JSON.exists() else "Missing")
    c2.metric("ATT&CK version", _meta.get("attack_version", "Unknown"))
    c3.metric("Technique count", _meta.get("technique_count", "Unknown"))

    if st.button("Sync latest Enterprise ATT&CK dataset", type="primary"):
        with st.spinner("Downloading and parsing the current Enterprise ATT&CK STIX dataset..."):
            try:
                meta = sync_attack_dataset()
                st.success(
                    f"ATT&CK sync complete. Version {meta.get('attack_version', 'unknown')}, "
                    f"{meta.get('technique_count', 0)} techniques."
                )
            except Exception as exc:
                st.error(f"ATT&CK sync failed: {exc}")

    st.divider()
    st.write(
        "The model proposes ATT&CK mappings for the latest Lab 2.1 evidence. Every returned technique ID is "
        "validated against the local ATT&CK cache. High and medium confidence go to Final; low confidence goes "
        "to Review; anything invalid or unsupported goes to Rejected."
    )

    map_col1, map_col2 = st.columns(2)

    with map_col1:
        if st.button("Run AI ATT&CK mapping", type="primary"):
            if not ATTACK_CACHE_JSON.exists():
                st.error("Sync the ATT&CK dataset first.")
            elif not selected_model:
                st.error("No usable Ollama model. Select or install one in the sidebar.")
            else:
                with st.spinner(f"Mapping with {selected_model}..."):
                    try:
                        result = run_attack_mapping(
                            evidence_path_arg=None,
                            ioc_path_arg=None,
                            attack_cache_arg=None,
                            model=selected_model,
                            candidate_count=candidate_count,
                            no_ai=False,
                        )
                        st.success(
                            f"Mapping complete. Final {len(result['final'])}, "
                            f"Review {len(result['review'])}, Rejected {len(result['rejected'])}."
                        )
                    except Exception as exc:
                        st.error(f"Mapping failed: {exc}")

    with map_col2:
        if st.button("Validate explicit IDs only (no AI)"):
            if not ATTACK_CACHE_JSON.exists():
                st.error("Sync the ATT&CK dataset first.")
            else:
                with st.spinner("Validating explicit ATT&CK IDs found in the evidence..."):
                    try:
                        result = run_attack_mapping(
                            evidence_path_arg=None,
                            ioc_path_arg=None,
                            attack_cache_arg=None,
                            model="",
                            candidate_count=candidate_count,
                            no_ai=True,
                        )
                        st.success(f"Validation complete. Final {len(result['final'])}.")
                    except Exception as exc:
                        st.error(f"Validation failed: {exc}")

    final_df = read_csv(LATEST_FINAL_MAPPING_CSV)
    review_df = read_csv(LATEST_REVIEW_MAPPING_CSV)
    rejected_df = read_csv(LATEST_REJECTED_MAPPING_CSV)

    t_final, t_review, t_rejected = st.tabs(["Final mappings", "Review mappings", "Rejected or uncertain"])
    with t_final:
        if final_df.empty:
            st.info("No final mappings yet.")
        else:
            st.dataframe(final_df, use_container_width=True, hide_index=True)
    with t_review:
        if review_df.empty:
            st.info("No review mappings yet.")
        else:
            st.dataframe(review_df, use_container_width=True, hide_index=True)
    with t_rejected:
        if rejected_df.empty:
            st.info("No rejected mappings yet.")
        else:
            st.dataframe(rejected_df, use_container_width=True, hide_index=True)


# --------------------------------------------------------------------------- #
# Tab 3: Navigator layer                                                       #
# --------------------------------------------------------------------------- #
with tab_navigator:
    st.subheader("Build an ATT&CK Navigator layer from final mappings")
    st.write(
        "Converts the final mappings into an importable Navigator JSON layer, tagged with the synced ATT&CK version."
    )

    if st.button("Generate Navigator layer", type="primary"):
        with st.spinner("Generating Navigator layer..."):
            try:
                result = run_navigator_layer(
                    mapping_csv=None,
                    layer_name="Module 2 AI-Mapped Threat Report Layer",
                    description=(
                        "ATT&CK Navigator layer generated from Module 2 final mappings. Mappings are AI-assisted, "
                        "validated against the current local ATT&CK cache, and should be analyst-reviewed."
                    ),
                    domain="enterprise-attack",
                    include_legend=True,
                )
                st.success(
                    f"Layer generated. {result['technique_count']} techniques, ATT&CK v{result['attack_version']}."
                )
            except Exception as exc:
                st.error(f"Navigator layer generation failed: {exc}")

    layer_text = read_text(LATEST_NAVIGATOR_LAYER_JSON)
    st.write(f"Layer file: `{LATEST_NAVIGATOR_LAYER_JSON}` - {path_status(LATEST_NAVIGATOR_LAYER_JSON)}")
    if layer_text:
        with st.expander("Preview Navigator layer JSON"):
            st.code(layer_text[:12000], language="json")
    st.markdown("Open ATT&CK Navigator: https://mitre-attack.github.io/attack-navigator/")


# --------------------------------------------------------------------------- #
# Tab 4: Hunting pack                                                          #
# --------------------------------------------------------------------------- #
with tab_hunting:
    st.subheader("Generate a SOC hunting pack")
    st.write(
        "Builds a Markdown hunting pack from the final mappings and IOCs: hunting questions plus starter Splunk SPL "
        "and Microsoft Sentinel or Defender KQL. These are starter hunts, not production detections. Tune to your "
        "SIEM field names before operational use."
    )

    if st.button("Generate hunting pack", type="primary"):
        with st.spinner("Generating hunting pack..."):
            try:
                result = run_hunting_pack(
                    mapping_csv=None,
                    review_csv=None,
                    iocs_csv=None,
                    source_url=st.session_state.get("final_url", ""),
                )
                st.success(
                    f"Hunting pack generated. {result['final_count']} final techniques, "
                    f"{result['markdown_length']:,} chars."
                )
            except Exception as exc:
                st.error(f"Hunting pack generation failed: {exc}")

    hunting_md = read_text(LATEST_HUNTING_PACK_MD)
    st.write(f"Markdown: `{LATEST_HUNTING_PACK_MD}` - {path_status(LATEST_HUNTING_PACK_MD)}")
    if hunting_md:
        with st.expander("Preview hunting pack"):
            st.markdown(hunting_md[:25000])


# --------------------------------------------------------------------------- #
# Tab 5: Deliverables + quality gate                                          #
# --------------------------------------------------------------------------- #
with tab_deliverables:
    st.subheader("Download artifacts")
    d1, d2, d3 = st.columns(3)

    with d1:
        st.markdown("**ATT&CK mapping**")
        download_if_exists("Final mapping CSV", LATEST_FINAL_MAPPING_CSV, "text/csv")
        download_if_exists("Final mapping JSON", LATEST_FINAL_MAPPING_JSON, "application/json")
        download_if_exists("Review mapping CSV", LATEST_REVIEW_MAPPING_CSV, "text/csv")
        download_if_exists("Rejected mapping CSV", LATEST_REJECTED_MAPPING_CSV, "text/csv")

    with d2:
        st.markdown("**Navigator and IOCs**")
        download_if_exists("Navigator layer JSON", LATEST_NAVIGATOR_LAYER_JSON, "application/json")
        download_if_exists("Lab 2.1 IOC CSV", LATEST_IOCS_CSV, "text/csv")

    with d3:
        st.markdown("**Hunting pack**")
        download_if_exists("Hunting pack Markdown", LATEST_HUNTING_PACK_MD, "text/markdown")
        download_if_exists("Hunting pack JSON", LATEST_HUNTING_PACK_JSON, "application/json")

    st.divider()
    st.subheader("Analyst quality gate")
    st.markdown(
        """
1. Do the final ATT&CK mappings match behavior described in the source report?
2. Are low-confidence mappings kept in the review bucket, not promoted to final?
3. Does the Navigator layer contain only final mappings, tagged with the correct ATT&CK version?
4. Does the hunting pack state that SPL and KQL are starter hunts, not production detections?
5. Are IOCs verified against the original report, with false positives separated?
6. Are queries tuned to the target SIEM field names before operational use?
"""
    )
