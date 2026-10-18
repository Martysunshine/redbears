from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AgentScratchpad:
    task: str
    plan: str = ""
    observations: list[str] = field(default_factory=list)

    def add_observation(self, obs: str) -> None:
        self.observations.append(obs)

    def to_context_string(self) -> str:
        parts = [f"TASK: {self.task}"]
        if self.plan:
            parts.append(f"PLAN:\n{self.plan}")
        if self.observations:
            obs_text = "\n".join(f"[{i}] {o}" for i, o in enumerate(self.observations, 1))
            parts.append(f"OBSERVATIONS:\n{obs_text}")
        return "\n\n".join(parts)
