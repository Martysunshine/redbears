from models.schemas import ArtifactAskRequest, ArtifactSummarizeRequest


def test_artifact_workflow_uses_verified_oyster_default():
    # 2026-10-08 — default promoted v1 -> v2 (same abliterated lineage, exported
    # to GGUF for V1-parity latency; held-out gate at parity). V1 stays
    # selectable as rollback. See oyster/docs/AI_HANDOFF.md.
    assert ArtifactAskRequest(question="What happened?").model == "oyster-dolphin-v2"
    assert ArtifactSummarizeRequest().model == "oyster-dolphin-v2"
