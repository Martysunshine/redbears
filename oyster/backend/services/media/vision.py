"""Local vision-language adapter.

Talks to Ollama (loopback, no cloud) with an image + prompt and returns a
structured analysis. Kept SEPARATE from the chat model — routing is:
chat/reasoning → dolphin/deepseek, image & video frames → ``config.VISION_MODEL``.

Model selection is resilient: the configured model is used if present in
``ollama list``; otherwise the first available fallback is chosen. If no vision
model is installed the caller receives a clear, actionable error.
"""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path

import httpx

import config
import log_config

_resolved_model: str | None = None
_checked = False


class VisionUnavailable(RuntimeError):
    """Raised when no local vision model is installed."""


async def _installed_models() -> list[str]:
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(config.OLLAMA_TAGS_URL)
            r.raise_for_status()
            return [m["name"] for m in r.json().get("models", [])]
    except Exception:
        return []


async def resolve_vision_model() -> str | None:
    """Pick the first installed vision model (configured → fallbacks). Cached."""
    global _resolved_model, _checked
    if _checked:
        return _resolved_model
    installed = await _installed_models()

    def _present(name: str) -> bool:
        # tolerate ":latest" omission both ways
        base = name.split(":")[0]
        return any(m == name or m.split(":")[0] == base for m in installed)

    for candidate in [config.VISION_MODEL, *config.VISION_MODEL_FALLBACKS]:
        if _present(candidate):
            # return the actually-installed tag
            for m in installed:
                if m == candidate or m.split(":")[0] == candidate.split(":")[0]:
                    _resolved_model = m
                    break
            break
    _checked = True
    return _resolved_model


def reset_cache() -> None:
    """Forget the resolved model (e.g. after pulling a new one)."""
    global _resolved_model, _checked
    _resolved_model, _checked = None, False


async def vision_available() -> bool:
    return (await resolve_vision_model()) is not None


async def _generate(model: str, prompt: str, image_path: str | Path,
                    timeout: float = 180.0) -> str:
    b64 = base64.b64encode(Path(image_path).read_bytes()).decode("ascii")
    payload = {
        "model": model,
        "prompt": prompt,
        "images": [b64],
        "stream": False,
        "options": {"temperature": 0.1},
    }
    async with httpx.AsyncClient(timeout=timeout) as client:
        r = await client.post(config.OLLAMA_GENERATE_URL, json=payload)
        r.raise_for_status()
        return r.json().get("response", "").strip()


def _extract_json(raw: str) -> dict | None:
    # models sometimes wrap JSON in prose / code fences
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.DOTALL)
    blob = fence.group(1) if fence else None
    if blob is None:
        brace = re.search(r"\{.*\}", raw, re.DOTALL)
        blob = brace.group(0) if brace else None
    if not blob:
        return None
    try:
        return json.loads(blob)
    except json.JSONDecodeError:
        return None


_ANALYSIS_PROMPT = (
    "You are a cybersecurity analyst examining an image (often a screenshot: "
    "terminal, code editor, config screen, error dialog, architecture/network "
    "diagram, or a photo). Study it carefully and reply with ONLY a JSON object, "
    "no prose, using exactly these keys:\n"
    "{\n"
    '  "description": "2-4 sentence factual description of what the image shows",\n'
    '  "visible_text": ["every distinct line of readable text / OCR, verbatim"],\n'
    '  "objects": ["notable UI elements, apps, devices, or objects"],\n'
    '  "security_observations": ["security-relevant facts: exposed versions, '
    'banners, misconfigurations, suspicious commands/processes, error messages, '
    'auth screens, network topology"],\n'
    '  "possible_secrets": ["any visible API keys, tokens, passwords, private '
    'keys — quote only a short prefix, never the full value"],\n'
    '  "error_messages": ["any error or warning text shown"]\n'
    "}\n"
    "If a field has nothing, use an empty array. Output JSON only."
)


def _as_list(v) -> list[str]:
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x).strip() for x in v if str(x).strip()]
    if isinstance(v, str):
        return [v.strip()] if v.strip() else []
    return [str(v)]


async def analyze_image(image_path: str, prompt: str | None = None,
                        project_id: str | None = None) -> dict:
    """Analyze one image locally. Returns the structured schema (see task spec).

    ``prompt`` overrides the default security-analysis instruction (used for
    targeted questions). Raises ``VisionUnavailable`` if no model is installed.
    """
    model = await resolve_vision_model()
    if not model:
        raise VisionUnavailable(
            "No local vision model installed. Run: ollama pull "
            f"{config.VISION_MODEL}  (or {', '.join(config.VISION_MODEL_FALLBACKS)})"
        )
    instruction = prompt or _ANALYSIS_PROMPT
    raw = await _generate(model, instruction, image_path)
    data = _extract_json(raw) or {}
    result = {
        "description": str(data.get("description") or (raw if not data else "")).strip(),
        "visible_text": _as_list(data.get("visible_text")),
        "objects": _as_list(data.get("objects")),
        "security_observations": _as_list(data.get("security_observations")),
        "possible_secrets": _as_list(data.get("possible_secrets")),
        "error_messages": _as_list(data.get("error_messages")),
        "metadata": {},
        "model": model,
    }
    log_config.audit("vision_analyze", {"project_id": project_id, "model": model,
                                        "image": Path(image_path).name})
    return result


async def describe_frame(image_path: str, context: str = "") -> dict:
    """Lightweight per-frame description for video keyframes."""
    prompt = (
        "This is a single frame from a screen-recording or video"
        + (f" ({context})" if context else "")
        + ". Reply with ONLY JSON: "
        '{"description":"1-2 sentences of what is on screen",'
        '"visible_text":["readable text / commands / errors, verbatim"],'
        '"security_observations":["security-relevant facts, if any"]}'
    )
    model = await resolve_vision_model()
    if not model:
        raise VisionUnavailable("No local vision model installed.")
    raw = await _generate(model, prompt, image_path, timeout=120.0)
    data = _extract_json(raw) or {}
    return {
        "description": str(data.get("description") or raw).strip()[:600],
        "visible_text": _as_list(data.get("visible_text")),
        "security_observations": _as_list(data.get("security_observations")),
    }
