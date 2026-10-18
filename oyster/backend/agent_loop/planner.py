from __future__ import annotations

from pathlib import Path

import config
from services import ollama_service

_PROMPTS_DIR = Path(__file__).parent / "prompts"


def _load(name: str) -> str:
    p = _PROMPTS_DIR / name
    return p.read_text(encoding="utf-8").strip() if p.exists() else ""


async def create_plan(task: str, model: str, tools_summary: str, memory_context: str = "") -> str:
    template = _load("planner_prompt.txt")
    prompt = (
        template.format(tools=tools_summary, task=task)
        if template and "{tools}" in template
        else (
            f"Create a concise, numbered step-by-step security execution plan for this task:\n\n"
            f"TASK: {task}\n\n"
            f"Available tools:\n{tools_summary}\n\n"
            f"Be specific. Reference which tools to use at each step. "
            f"Prioritize read-only reconnaissance first."
        )
    )
    if memory_context:
        prompt = f"{memory_context}\n\n---\n\n{prompt}"
    return await ollama_service.generate(prompt, config.resolve_model(model, config.REASONING_MODEL))
