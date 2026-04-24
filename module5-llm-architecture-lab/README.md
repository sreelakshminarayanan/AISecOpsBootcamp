# Module 5 — LLM Architecture & Attacker Mental Model Lab

Bootcamp: AI in SecOps Bootcamp — Building & Breaking LLMs in Practice  
Module: Module 5 — LLM Architecture & The Attacker’s Mental Model

## Purpose

This lab is designed to teach how LLM security issues work in practice.

The goal is not to run scripted toy outputs. The goal is to interact with real local LLMs and observe how model behavior changes based on:

- tokenisation
- prompt structure
- system instructions
- retrieved documents
- temperature and sampling
- context pressure
- weak vs hardened prompt design

## Core Principles

1. Labs must use actual model responses.
2. Outputs must not be hardcoded.
3. Participants should observe variability and failure modes.
4. Every attack should map to a real-world LLM application risk.
5. Every attack should include a defensive learning point.

## Lab Components

- Lab 5.0 — Environment validation
- Lab 5.1 — Tokenisation reconnaissance
- Lab 5.2 — System prompt trust boundary failure
- Lab 5.3 — Temperature and attack reliability
- Lab 5.4 — Indirect prompt injection via retrieved document
- Lab 5.5 — Context window pressure test
- Lab 5.6 — Model behavior comparison
- Lab 5.7 — Optional Garak mini-scan

## Safety Boundary

This lab uses controlled examples focused on prompt security, trust boundaries, and model behavior.

Participants should not use the environment to generate real-world harmful instructions, credential theft, malware, or unauthorized exploitation steps.

## Recommended Models

Primary model:

```bash
ollama pull llama3.1:8b

## Recommended Models



