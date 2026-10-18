# AI / LLM / Agent Security

AI red teams test whether an AI system can be manipulated, abused, made unsafe, or leak information. The most serious *agent* risk is usually not a bad answer — it is an agent with excessive permissions taking an **irreversible action**.

## OWASP Top 10 for LLM Applications (key risks)
- **Prompt Injection (direct)** — user input overrides system instructions ("ignore previous instructions").
- **Indirect prompt injection** — malicious instructions hidden in retrieved documents, web pages, or tool output that the model then follows. **Treat all retrieved content as untrusted data, never instructions.**
- **Sensitive Information Disclosure** — model leaks secrets, PII, or other users' data (cross-tenant).
- **Improper Output Handling** — downstream systems trust model output (e.g., executing generated commands/SQL).
- **Excessive Agency** — too many tools/permissions/autonomy; the fix is least privilege + human approval for consequential actions.
- **Retrieval/Data Poisoning** — poisoning the training data or the RAG knowledge base to bias/backdoor answers.
- **System Prompt Leakage**, **Vector/Embedding Weaknesses**, **Misinformation (hallucination in high-risk workflows)**, **Unbounded Consumption** (denial-of-wallet / resource abuse).

## Defensive patterns (how Oyster itself is built)
- Retrieved webpages/documents/tool output are **untrusted data**; they must never rewrite system policy or auto-execute commands.
- **Human approval** gates consequential, intrusive, or irreversible actions; provide a visible emergency stop.
- **Least privilege** for tools; scope enforced **in code**, not just the prompt.
- **Redact secrets** from logs and model context. Separate **verified facts** (retrieved, cited) from **model reasoning**.
- Keep project/tenant data isolated; defend against cross-user exposure.

## Testing tools
- **garak** — LLM vulnerability scanner (prompt injection, jailbreak, leakage probes).
- **PyRIT** (Microsoft) — risk-identification toolkit for generative AI.
- **promptfoo** / **Giskard** — eval harnesses and red-team test suites.
- Plus normal application-security tooling for the surrounding app/API.

## References
- OWASP Top 10 for LLM Applications — https://genai.owasp.org/llm-top-10/
- NIST AI Risk Management Framework — https://www.nist.gov/itl/ai-risk-management-framework
- garak — https://github.com/NVIDIA/garak
