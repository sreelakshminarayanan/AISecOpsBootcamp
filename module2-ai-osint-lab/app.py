from pathlib import Path

import pandas as pd
import streamlit as st
from bs4 import BeautifulSoup

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
from tools.ollama_client import ask_ollama


st.set_page_config(
    page_title="Lab 2.1 AI OSINT Workbench",
    layout="wide",
)


def dataframe_from_rows(rows: list) -> pd.DataFrame:
    if not rows:
        return pd.DataFrame()

    return pd.DataFrame(rows)


def file_download_button(label: str, file_path: Path, mime: str):
    file_path = Path(file_path)

    if file_path.exists():
        st.download_button(
            label=label,
            data=file_path.read_bytes(),
            file_name=file_path.name,
            mime=mime,
        )


st.title("Lab 2.1: AI Threat Report IOC Extractor")

st.caption(
    "Paste any public threat intel report URL. Extract validated IOCs. Separate false positives. Generate AI-assisted summaries using local Ollama."
)

st.markdown(
    """
This is a local AI-powered OSINT workbench.

Workflow:

1. Paste a public threat report URL.
2. The app checks robots.txt.
3. The app fetches the page passively.
4. The app extracts article text and links.
5. The app extracts and validates IOCs.
6. The app separates accepted observables from likely false positives.
7. The app generates two AI outputs:
   - Easy Summary for junior analysts, managers, GRC, and non-specialist readers.
   - Analyst Brief for SOC, threat intelligence, and detection engineering.
8. The app saves JSON, CSV, and Markdown outputs for Lab 2.2 enrichment.

Use only public threat reports or authorized sources. Do not use this tool for scanning, exploitation, brute forcing, authentication bypass, or private content.
"""
)

with st.sidebar:
    st.header("Controls")

    model = st.selectbox(
        "Local Ollama Model",
        ["llama3.2:3b", "llama3.1:8b", "mistral:7b"],
        index=0,
    )

    respect_robots = st.checkbox(
        "Respect robots.txt stop condition",
        value=True,
        help="If enabled, the app stops when robots.txt disallows fetching this URL for the configured user agent.",
    )

    user_agent = st.text_input(
        "User-Agent",
        value=DEFAULT_USER_AGENT,
    )

    generate_easy_summary = st.checkbox(
        "Generate easy summary",
        value=True,
        help="Creates a simple explanation of the report for junior analysts, managers, GRC, or non-specialist readers.",
    )

    generate_ai = st.checkbox(
        "Generate analyst brief",
        value=True,
        help="Creates a SOC and threat-intel style analyst brief with detection and hunting ideas.",
    )

    show_raw_evidence = st.checkbox(
        "Show raw evidence JSON",
        value=False,
    )

    st.divider()
    st.markdown("### Safe Usage")
    st.write("Use public threat reports or authorized sources only.")
    st.write("This tool performs passive page retrieval and parsing.")
    st.write("No port scanning. No exploitation. No authentication bypass. No crawling private content.")

    st.divider()
    st.markdown("### Example sources")
    st.write("Paste a specific report URL manually into the input field.")
    st.code("https://unit42.paloaltonetworks.com/")
    st.code("https://www.microsoft.com/en-us/security/blog/")
    st.code("https://blog.talosintelligence.com/")
    st.code("https://www.mandiant.com/resources/blog")


with st.form("threat_report_input_form"):
    url = st.text_input(
        "Threat Report URL",
        value="",
        placeholder="Paste any public threat intel report URL here",
    )

    submitted = st.form_submit_button(
        "Analyze Threat Report",
        type="primary",
    )


if submitted:
    try:
        if not url.strip():
            st.warning("Please paste a threat report URL first.")
            st.stop()

        url = normalize_url(url.strip())

        st.subheader("1. Source URL")
        st.write(url)

        st.subheader("2. robots.txt Check")

        with st.spinner("Checking robots.txt..."):
            robots = check_robots(url, user_agent)

        st.json(robots)

        if respect_robots and robots.get("allowed") is False:
            st.error(
                "robots.txt does not allow this fetch for the configured user agent. "
                "Stopping because the robots.txt stop condition is enabled."
            )
            st.stop()

        st.subheader("3. Fetching Report Page")

        with st.spinner("Fetching public report page..."):
            fetched = fetch_html(url, user_agent)

        http_summary = {
            "input_url": url,
            "final_url": fetched["final_url"],
            "status_code": fetched["status_code"],
            "content_type": fetched["content_type"],
            "server": fetched["headers"].get("Server"),
            "x_powered_by": fetched["headers"].get("X-Powered-By"),
        }

        st.json(http_summary)

        if fetched["status_code"] >= 400:
            st.error(f"HTTP error: {fetched['status_code']}")
            st.stop()

        if not fetched.get("html"):
            st.error("No HTML content was returned. This MVP expects a public HTML threat report page.")
            st.stop()

        soup = BeautifulSoup(fetched["html"], "lxml")

        st.subheader("4. Extracting Article Text, Links, and IOCs")

        with st.spinner("Parsing article text and links..."):
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

        with st.spinner("Extracting and validating IOCs from article text..."):
            iocs = extract_iocs_from_text(extraction_text)

        evidence = build_evidence(
            url=url,
            fetched=fetched,
            article=article,
            links=links,
            iocs=iocs,
            robots=robots,
        )

        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric("Article text length", evidence["article"]["article_text_length"])

        with col2:
            st.metric("Links extracted", evidence["link_count"])

        with col3:
            st.metric("Accepted observables", evidence["accepted_ioc_count"])

        with col4:
            st.metric("Rejected false positives", evidence["rejected_false_positive_count"])

        st.subheader("5. Article Metadata")

        st.write(f"**Title:** {article['title'] or 'Not found'}")
        st.write(f"**Extractor selector used:** `{article['article_selector_used']}`")
        st.write(f"**Final URL:** {fetched['final_url']}")

        description = article["meta"].get("description") or article["meta"].get("og:description")

        if description:
            st.write(f"**Meta description:** {description}")

        with st.expander("Article text preview"):
            st.write(article["article_text"][:6000])

        st.subheader("6. IOC Counts")
        st.json(evidence["ioc_counts"])

        st.subheader("7. Validated Extracted IOCs")

        accepted_df = dataframe_from_rows(build_ioc_rows(iocs))

        if accepted_df.empty:
            st.warning("No validated IOCs were extracted from this page.")
        else:
            st.dataframe(
                accepted_df,
                use_container_width=True,
                hide_index=True,
            )

            st.download_button(
                label="Download Validated IOCs CSV",
                data=accepted_df.to_csv(index=False).encode("utf-8"),
                file_name="lab2_1_validated_iocs.csv",
                mime="text/csv",
            )

        st.subheader("8. Rejected False Positives")

        rejected_df = dataframe_from_rows(build_rejected_rows(iocs))

        if rejected_df.empty:
            st.info("No rejected false positives recorded.")
        else:
            st.dataframe(
                rejected_df,
                use_container_width=True,
                hide_index=True,
            )

            st.download_button(
                label="Download Rejected False Positives CSV",
                data=rejected_df.to_csv(index=False).encode("utf-8"),
                file_name="lab2_1_rejected_false_positives.csv",
                mime="text/csv",
            )

        st.subheader("9. Extracted Links")

        link_df = pd.DataFrame(links)

        if link_df.empty:
            st.info("No links extracted.")
        else:
            st.dataframe(
                link_df.head(200),
                use_container_width=True,
                hide_index=True,
            )

            st.download_button(
                label="Download Extracted Links CSV",
                data=link_df.to_csv(index=False).encode("utf-8"),
                file_name="lab2_1_extracted_links.csv",
                mime="text/csv",
            )

        st.subheader("10. AI Outputs")

        ai_brief = ""
        easy_summary = ""

        easy_summary_tab, analyst_brief_tab = st.tabs(
            [
                "Easy Summary",
                "Analyst Brief",
            ]
        )

        if generate_easy_summary:
            with easy_summary_tab:
                with st.spinner("Generating easy-to-understand threat report summary using local Ollama..."):
                    easy_summary = ask_ollama(
                        build_easy_summary_prompt(
                            source_url=fetched["final_url"],
                            article=article,
                            iocs=iocs,
                            links=links,
                        ),
                        model=model,
                        temperature=0.2,
                        num_predict=1200,
                    )

                st.markdown(easy_summary)

                st.download_button(
                    label="Download Easy Summary Markdown",
                    data=easy_summary.encode("utf-8"),
                    file_name="lab2_1_easy_summary.md",
                    mime="text/markdown",
                )
        else:
            with easy_summary_tab:
                st.info("Easy summary generation is disabled. Enable it from the sidebar if needed.")

        if generate_ai:
            with analyst_brief_tab:
                with st.spinner("Generating analyst OSINT brief using local Ollama..."):
                    ai_brief = ask_ollama(
                        build_ai_prompt(
                            source_url=fetched["final_url"],
                            article=article,
                            iocs=iocs,
                            links=links,
                        ),
                        model=model,
                        temperature=0.2,
                        num_predict=1400,
                    )

                st.markdown(ai_brief)

                st.download_button(
                    label="Download Analyst Brief Markdown",
                    data=ai_brief.encode("utf-8"),
                    file_name="lab2_1_ai_osint_brief.md",
                    mime="text/markdown",
                )
        else:
            with analyst_brief_tab:
                st.info("Analyst brief generation is disabled. Enable it from the sidebar if needed.")

        st.subheader("11. Save Outputs for Lab 2.2")

        with st.spinner("Saving evidence, IOC CSV, false-positive CSV, links CSV, and AI outputs..."):
            paths = save_outputs(
                source_url=fetched["final_url"],
                evidence=evidence,
                ai_brief=ai_brief,
                easy_summary=easy_summary,
            )

        st.success("Outputs saved successfully.")

        st.write(f"Evidence JSON: `{paths['json']}`")
        st.write(f"IOC CSV: `{paths['ioc_csv']}`")
        st.write(f"Rejected false positives CSV: `{paths['rejected_csv']}`")
        st.write(f"Latest IOC CSV: `{paths['latest_iocs']}`")
        st.write(f"Latest rejected false positives CSV: `{paths['latest_rejected']}`")
        st.write(f"Links CSV: `{paths['links_csv']}`")
        st.write(f"Analyst Brief: `{paths['brief']}`")
        st.write(f"Easy Summary: `{paths['easy_summary']}`")

        download_col1, download_col2, download_col3, download_col4, download_col5 = st.columns(5)

        with download_col1:
            file_download_button(
                "Download Evidence JSON",
                paths["json"],
                "application/json",
            )

        with download_col2:
            file_download_button(
                "Download Saved IOC CSV",
                paths["ioc_csv"],
                "text/csv",
            )

        with download_col3:
            file_download_button(
                "Download Rejected FP CSV",
                paths["rejected_csv"],
                "text/csv",
            )

        with download_col4:
            file_download_button(
                "Download Analyst Brief",
                paths["brief"],
                "text/markdown",
            )

        with download_col5:
            file_download_button(
                "Download Easy Summary",
                paths["easy_summary"],
                "text/markdown",
            )

        if show_raw_evidence:
            st.subheader("Raw Evidence JSON")
            st.json(evidence)

        st.divider()
        st.markdown(
            """
### Analyst validation checklist

Before using the AI outputs, verify:

1. Did the model invent any IOCs?
2. Did the validated IOCs appear in the original article text?
3. Did rejected items correctly include JavaScript, CSS, SVG, config, or benign dependency artifacts?
4. Did the model distinguish confirmed observations from hypotheses?
5. Did it avoid calling an observable malicious without enrichment evidence?
6. Is the final validated IOC CSV suitable to pass into Lab 2.2 enrichment?
7. Is the easy summary understandable for junior analysts or non-specialist readers?
8. Is the analyst brief specific enough for SOC, TI, or detection engineering follow-up?
"""
        )

    except Exception as exc:
        st.error(f"Error: {exc}")