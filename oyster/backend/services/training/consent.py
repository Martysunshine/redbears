"""Consent gate for the training pipeline — off by default, project-scoped.

This is the code-level enforcement of "Allow my data for model improvement":
no project's conversations may be built into a training dataset, and no job
may run, unless this returns True for that project. There is no global
override and no implicit inheritance from one project to another.
"""

from __future__ import annotations

from . import store


class ConsentRequired(RuntimeError):
    pass


def is_allowed(project_id: str) -> bool:
    return store.get_consent(project_id)["allowed"]


def set_allowed(project_id: str, allowed: bool) -> dict:
    return store.set_consent(project_id, allowed)


def assert_allowed(project_id: str) -> None:
    if not is_allowed(project_id):
        raise ConsentRequired(
            f"Project '{project_id}' has not opted in to training data use "
            "('Allow my data for model improvement' is off, the default)."
        )
