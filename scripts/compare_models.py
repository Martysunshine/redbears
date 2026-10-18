#!/usr/bin/env python3
"""Run the same cybersecurity questions through the Red Bears streaming endpoint for several
answer models and record latency + citation checks. Writes JSON; prints a summary.
Usage: scripts/compare_models.py out.json [rerank=1|0]   (backend must be running)"""
import json, re, sys, time, urllib.request

API = "http://127.0.0.1:8101/knowledge/ask/stream"
MODELS = ["oyster-dolphin-v2", "huihui-qwen3.8-27b"]
QUESTIONS = [
    "How does Kerberoasting work and how do I detect it?",
    "What is the CVE identifier of the Log4Shell vulnerability and why is it critical?",
    "How do I mitigate CWE-89 SQL injection?",
    "What does MITRE ATT&CK technique T1055 process injection involve and how can defenders detect it?",
    "What are the first incident response steps for a ransomware outbreak?",
]

def run(q, model, rerank):
    req = urllib.request.Request(API, data=json.dumps({"question": q, "model": model, "rerank": rerank, "top_k": 5}).encode(),
                                 headers={"Content-Type": "application/json"})
    out = {"model": model, "question": q}
    t0 = time.time(); toks = 0
    for line in urllib.request.urlopen(req, timeout=900):
        f = json.loads(line)
        if f["type"] == "meta":
            out["rerank"] = f["rerank"]; out["retrieval_ms"] = f["retrieval_ms"]
            out["citations"] = [{"n": c["n"], "chunk_id": c["chunk_id"], "source_url": c.get("source_url"),
                                 "title": c.get("source_title") or c.get("document"), "retrieval_rank": c.get("retrieval_rank"),
                                 "rerank_score": c.get("rerank_score"), "chunk": c["chunk"]} for c in f["citations"]]
        elif f["type"] == "token": toks += 1
        elif f["type"] == "done":
            out.update(answer=f["answer"], quality_flags=f["quality_flags"], ttft_ms=f["ttft_ms"], total_ms=f["total_ms"], stream_chunks=toks)
        elif f["type"] == "error": out["error"] = f["detail"]
    n = len(out.get("citations", []))
    marks = [int(m) for m in re.findall(r"\[(\d+)\]", out.get("answer", ""))]
    out["citation_markers"] = sorted(set(marks))
    out["markers_out_of_range"] = [m for m in set(marks) if not 1 <= m <= n]
    return out

if __name__ == "__main__":
    path = sys.argv[1]; rerank = (sys.argv[2] if len(sys.argv) > 2 else "1") == "1"
    results = []
    for model in MODELS:
        for q in QUESTIONS:
            r = run(q, model, rerank); results.append(r)
            print(f"{model:20s} ttft={r.get('ttft_ms')} total={r.get('total_ms')} markers={r['citation_markers']} "
                  f"bad={r['markers_out_of_range']} flags={r.get('quality_flags')} err={r.get('error')} :: {q[:50]}", flush=True)
            json.dump(results, open(path, "w"), indent=1)
