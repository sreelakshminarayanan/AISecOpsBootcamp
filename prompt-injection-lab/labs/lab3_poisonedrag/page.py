"""Lab 3: non-deterministic RAG poisoning engagement workbench."""
from __future__ import annotations

import time
import uuid

import streamlit as st

from core.config import DEFAULT_MODEL
from core.logging import JSONLLogger
from core.ollama_client import OllamaConnectionError, OllamaModelError, OllamaService
from labs.lab3_poisonedrag.knowledge_base import (
    DEFAULT_ATTACKER_CLAIM, DEFAULT_CORPUS, DEFAULT_QUESTION, POISON_STRATEGIES,
    RAGEngine, craft_poison_texts, parse_documents,
)
from labs.lab3_poisonedrag.rag_judge import generate_rag_answer, judge_poisoned_answer

LAB_ID = "lab3_poisonedrag"


@st.cache_resource(show_spinner=False)
def _ollama() -> OllamaService:
    return OllamaService()


def _state() -> None:
    if "lab3_session" not in st.session_state:
        st.session_state.lab3_session = uuid.uuid4().hex[:12]
        st.session_state.lab3_logger = JSONLLogger(LAB_ID, st.session_state.lab3_session)
        st.session_state.lab3_runs = []


def _model_picker(svc: OllamaService) -> str:
    try:
        models = svc.list_models()
    except (OllamaConnectionError, OllamaModelError):
        models = []
    if models:
        index = models.index(DEFAULT_MODEL) if DEFAULT_MODEL in models else 0
        return st.sidebar.selectbox("Target model", models, index=index, key="lab3_model")
    st.sidebar.warning("Ollama unavailable. You can configure the exercise, but execution requires a local model.")
    return st.sidebar.text_input("Target model", DEFAULT_MODEL, key="lab3_model_text")


def _run_pipeline(svc, model, clean_docs, poison_docs, question, marker, top_k, temperature, seed, trusted_only, hardened, label):
    engine = RAGEngine()
    summary = engine.build(clean_docs, poison_docs)
    retrieval = engine.retrieve(question, top_k, trusted_only)
    started = time.perf_counter()
    answer = generate_rag_answer(svc, model, question, retrieval, temperature, seed, hardened)
    latency = int((time.perf_counter() - started) * 1000)
    verdict = judge_poisoned_answer(answer, marker, retrieval.poisoned_count())
    return {"label": label, "summary": summary, "retrieval": retrieval, "answer": answer, "verdict": verdict, "latency_ms": latency}


def _show_run(run: dict) -> None:
    retrieval, verdict = run["retrieval"], run["verdict"]
    colors = {"GENERATION_COMPROMISED": "🚨", "RETRIEVAL_COMPROMISED": "🟠", "BLOCKED": "✅", "ERROR": "⚠️"}
    st.markdown(f"#### {run['label']}")
    a, b, c, d = st.columns(4)
    a.metric("Poison in KB", run["summary"]["poison_docs"])
    b.metric("Poison in top-k", f"{retrieval.poisoned_count()} / {len(retrieval.docs)}")
    c.metric("Outcome", f"{colors.get(verdict.verdict, '')} {verdict.verdict}")
    d.metric("LLM latency", f"{run['latency_ms']} ms")
    st.caption(verdict.reasoning)
    with st.expander("Retrieval trace", expanded=True):
        for rank, doc in enumerate(retrieval.docs, 1):
            tag = "POISON / untrusted" if doc.poisoned else "CLEAN / trusted"
            similarity = f"{doc.similarity:.3f}" if doc.similarity is not None else "n/a"
            st.markdown(f"**#{rank} · {tag} · similarity proxy {similarity} · `{doc.doc_id}`**")
            st.caption(doc.text)
    st.markdown("**Live target-model answer**")
    st.info(run["answer"] or "(empty answer)")


def render() -> None:
    _state()
    svc = _ollama()
    logger = st.session_state.lab3_logger

    st.markdown("## Lab 3: RAG Poisoning Engagement")
    st.caption("Design, execute, observe, and defend a knowledge-base poisoning attack. Retrieval and answers are computed live; success is not guaranteed.")

    model = _model_picker(svc)
    top_k = st.sidebar.slider("Retrieval top-k", 1, 8, 3)
    temperature = st.sidebar.slider("Target temperature", 0.0, 1.5, 0.5, 0.1)
    randomize = st.sidebar.checkbox("Randomize each run", True, help="When enabled, poison wording and model sampling can vary between runs.")
    seed_value = st.sidebar.number_input("Reproducibility seed", 0, 999999, 42, disabled=randomize)
    trusted_only = st.sidebar.checkbox("Defense: trusted sources only", False)
    hardened = st.sidebar.checkbox("Defense: instruction/data separation", False)

    with st.expander("Engagement brief", expanded=True):
        st.markdown("**Objective:** get attacker-controlled content into top-k retrieval and then influence the target model's answer. These are scored as two separate gates. Use only the fictional `.example.test` training tenant.")

    left, right = st.columns(2)
    with left:
        st.markdown("### 1. Define the target")
        question = st.text_area("Target user question", DEFAULT_QUESTION, height=100)
        attacker_claim = st.text_area("Desired malicious answer", DEFAULT_ATTACKER_CLAIM, height=120)
        marker = st.text_input("Unique success marker", "securefin-reset.example.test", help="A distinctive inert string expected only if the model adopts the malicious claim.")
    with right:
        st.markdown("### 2. Configure the attack")
        strategy = st.selectbox("Poison strategy", list(POISON_STRATEGIES))
        st.caption(POISON_STRATEGIES[strategy])
        poison_count = st.slider("Poison documents", 0, 10, 3)
        custom_poison = st.text_area("Optional custom poison documents (separate with ---)", "", height=130)

    st.markdown("### 3. Edit the victim knowledge base")
    corpus_raw = st.text_area("Clean documents (separate documents with a line containing ---)", DEFAULT_CORPUS, height=240)

    seed = None if randomize else int(seed_value)
    generated_poison = craft_poison_texts(question, attacker_claim, strategy, poison_count, seed)
    custom_docs = parse_documents(custom_poison)
    poison_docs = generated_poison + custom_docs
    with st.expander(f"Preview attacker payloads ({len(poison_docs)})"):
        if poison_docs:
            for i, doc in enumerate(poison_docs, 1):
                st.code(f"POISON {i}\n{doc}", language="text")
        else:
            st.caption("No poison configured. This is a clean control run.")

    compare = st.checkbox("Run clean baseline and poisoned experiment side by side", True)
    if st.button("Execute engagement", type="primary", use_container_width=True):
        clean_docs = parse_documents(corpus_raw)
        if not question.strip() or not clean_docs:
            st.error("Provide a target question and at least one clean document.")
            return
        if poison_docs and not marker.strip():
            st.error("Define a unique success marker before scoring a poisoned run.")
            return
        actual_seed = None if randomize else int(seed_value)
        runs = []
        with st.spinner("Embedding documents, retrieving context, and calling the target LLM..."):
            if compare:
                runs.append(_run_pipeline(svc, model, clean_docs, [], question, marker, top_k, temperature, actual_seed, trusted_only, hardened, "Clean control"))
            runs.append(_run_pipeline(svc, model, clean_docs, poison_docs, question, marker, top_k, temperature, actual_seed, trusted_only, hardened, "Poisoned experiment"))
        st.session_state.lab3_runs = runs
        for run in runs:
            logger.log({"event": "rag_engagement", "run_label": run["label"], "model": model, "question": question, "strategy": strategy, "clean_docs": len(clean_docs), "poison_docs": len(poison_docs) if run["label"] == "Poisoned experiment" else 0, "top_k": top_k, "trusted_only": trusted_only, "hardened_prompt": hardened, "temperature": temperature, "seed": actual_seed, "retrieved_ids": [d.doc_id for d in run["retrieval"].docs], "poison_retrieved": run["retrieval"].poisoned_count(), "answer": run["answer"], "verdict": run["verdict"].to_dict(), "latency_ms": run["latency_ms"]})

    if st.session_state.lab3_runs:
        st.divider()
        st.markdown("### 4. Evidence and outcome")
        for run in st.session_state.lab3_runs:
            _show_run(run)
        st.info("A changed answer alone is not proof. The trace shows the causal chain: corpus mutation → vector rank → context exposure → model output → marker-based outcome.")
