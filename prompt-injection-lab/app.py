"""Prompt Injection Lab Streamlit app entry point.

Run with:
    streamlit run app.py

The sidebar only shows labs that are implemented and operational.
"""
from __future__ import annotations

from typing import Callable

import streamlit as st

from core.config import APP_ICON, APP_TITLE
from labs.lab1_concierge import page as lab1_page
from labs.lab2_slowboil import page as lab2_page


st.set_page_config(
    page_title=APP_TITLE,
    page_icon=APP_ICON,
    layout="wide",
    initial_sidebar_state="expanded",
)


LABS: dict[str, Callable[[], None]] = {
    "Lab 1: The Leaky Concierge": lab1_page.render,
    "Lab 2: The Slow Boil": lab2_page.render,
}


def _render_app_sidebar() -> str:
    with st.sidebar:
        st.markdown(f"# {APP_ICON} {APP_TITLE}")
        st.caption(
            "Hands-on lab series for LLM prompt injection and jailbreak testing. "
            "Only operational labs are shown."
        )
        st.divider()
        selected = st.radio(
            "Select lab",
            list(LABS.keys()),
            index=0,
            key="app_lab_selector",
        )
        st.divider()
    return selected


def main() -> None:
    selected = _render_app_sidebar()
    LABS[selected]()


if __name__ == "__main__":
    main()
