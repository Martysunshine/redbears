from services.chat_policy import named_reference_subject


def test_copula_tool_question_requires_evidence():
    assert named_reference_subject(
        "What is the Fingerprinty security tool and where is its official documentation?"
    ) == "Fingerprinty"
