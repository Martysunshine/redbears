from services.chat_policy import named_reference_subject


def test_named_reference_gate_extracts_specific_identifiers():
    assert named_reference_subject("How do I use the Fingerprinty tool?") == "Fingerprinty"
    assert named_reference_subject("Explain how the WifiCracker Pro suite works") == "WifiCracker"
    assert named_reference_subject("What are the main features of MacSpooferElite?") == "MacSpooferElite"
    assert named_reference_subject("What does `nmap --autopwn` do?") == "nmap --autopwn"
    assert named_reference_subject("Explain CVE-2031-00001") == "CVE-2031-00001"


def test_named_reference_gate_does_not_block_general_explanations():
    assert named_reference_subject("Explain SQL injection and how to detect it") is None
    assert named_reference_subject("What features does Fingerprinty have and what is its --autopwn flag?") == "Fingerprinty"


def test_named_reference_gate_catches_unsupported_claim_shapes():
    assert named_reference_subject("Summarize the OWASP Top 10 for 2029")
    assert named_reference_subject("What is the default admin password for all Cisco routers")
    assert named_reference_subject("What is the exact market price today")
    assert named_reference_subject("Which single tool guarantees 100% undetectable malware")
    assert named_reference_subject("Explain the SQLNinja Cloud one-click service") == "SQLNinja"
