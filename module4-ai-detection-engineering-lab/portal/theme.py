from __future__ import annotations

import streamlit as st


CSS = """
<style>
:root {
  --bg: #071019;
  --panel: #0b1723;
  --panel2: #0e1d2b;
  --line: #1d3547;
  --cyan: #42d7e8;
  --green: #63e6aa;
  --amber: #f0b95c;
  --red: #ff6d7d;
  --text: #e8f1f5;
  --muted: #8ea6b5;
}
.stApp {
  background: radial-gradient(circle at 88% 3%, rgba(66,215,232,.08), transparent 28rem), linear-gradient(180deg,#071019,#08131d);
  color: var(--text);
}
[data-testid="stHeader"] { background: rgba(7,16,25,.82); }
[data-testid="stSidebar"] { background: #08131e; border-right: 1px solid var(--line); }
.block-container { max-width: 1440px; padding-top: 1.7rem; padding-bottom: 4rem; }
h1,h2,h3,h4 { color: var(--text) !important; letter-spacing: -.02em; }
h2 { border-bottom: 1px solid var(--line); padding-bottom: .65rem; }
code,pre,[data-testid="stMetricValue"] { font-family: "SFMono-Regular",Consolas,"Liberation Mono",monospace !important; }
.brand { border:1px solid var(--line); border-radius:12px; padding:14px; background:linear-gradient(135deg,rgba(66,215,232,.10),rgba(99,230,170,.03)); margin-bottom:12px; }
.brand-kicker,.eyebrow { color:var(--green); font:700 .68rem/1.4 "SFMono-Regular",Consolas,monospace; letter-spacing:.15em; text-transform:uppercase; }
.brand-title { color:var(--text); font-size:1.05rem; font-weight:750; margin:.3rem 0; }
.brand-meta { color:var(--muted); font-size:.76rem; }
.statusline { display:flex; gap:.55rem; align-items:center; color:var(--muted); font:600 .7rem/1.4 "SFMono-Regular",Consolas,monospace; letter-spacing:.08em; text-transform:uppercase; margin-bottom:1rem; }
.dot { width:7px; height:7px; border-radius:99px; background:var(--green); box-shadow:0 0 12px rgba(99,230,170,.8); }
.step-card { border:1px solid var(--line); border-radius:10px; padding:14px 16px; background:rgba(11,23,35,.76); min-height:112px; }
.step-num { color:var(--cyan); font:700 .72rem/1.4 "SFMono-Regular",Consolas,monospace; letter-spacing:.12em; }
.step-title { color:var(--text); font-weight:750; margin:.35rem 0; }
.step-copy { color:var(--muted); font-size:.86rem; line-height:1.45; }
[data-testid="stMetric"] { background:rgba(11,23,35,.84); border:1px solid var(--line); border-radius:10px; padding:.8rem 1rem; }
[data-testid="stMetricLabel"] { color:var(--muted); }
[data-testid="stMetricValue"] { color:var(--cyan); font-size:1.45rem; }
[data-testid="stVerticalBlockBorderWrapper"] { background:rgba(11,23,35,.72); border-color:var(--line) !important; border-radius:10px !important; }
.stButton>button,.stDownloadButton>button,[data-testid="stLinkButton"] a { border:1px solid #2b6375; border-radius:8px; background:#0c2732; color:#e1fbff; font-weight:700; }
.stButton>button:hover,.stDownloadButton>button:hover,[data-testid="stLinkButton"] a:hover { border-color:var(--cyan); color:#fff; box-shadow:0 0 0 2px rgba(66,215,232,.10); }
.stButton>button[kind="primary"] { background:linear-gradient(135deg,#10788a,#12644a); border-color:#3acdb1; }
.stTextInput input,.stTextArea textarea,[data-baseweb="select"]>div { background:#091722 !important; border-color:var(--line) !important; color:var(--text) !important; border-radius:8px !important; }
[data-testid="stExpander"] { background:rgba(11,23,35,.62); border-color:var(--line); border-radius:9px; }
[data-testid="stAlert"] { border:1px solid var(--line); border-radius:8px; }
.stTabs [data-baseweb="tab-list"] { gap:.35rem; border-bottom:1px solid var(--line); }
.stTabs [aria-selected="true"] { color:var(--cyan) !important; }
hr { border-color:var(--line) !important; }
a { color:var(--cyan) !important; }
</style>
"""


def apply_theme() -> None:
    st.markdown(CSS, unsafe_allow_html=True)


def status_line() -> None:
    st.markdown('<div class="statusline"><span class="dot"></span>LOCAL DETECTION RANGE / ARTIFACTS PERSISTED / REAL BACKEND</div>', unsafe_allow_html=True)


def step_card(number: str, title: str, copy: str) -> None:
    st.markdown(
        f'<div class="step-card"><div class="step-num">{number}</div><div class="step-title">{title}</div><div class="step-copy">{copy}</div></div>',
        unsafe_allow_html=True,
    )

