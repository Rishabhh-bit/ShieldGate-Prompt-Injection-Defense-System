from collections import Counter

from redteam.runner import baseline, load_cases


def test_baseline_and_corpus():
    counts = Counter(case["category"] for case in load_cases())
    assert counts == {
        "direct": 10,
        "indirect_email": 10,
        "indirect_web": 8,
        "indirect_document": 6,
        "obfuscation": 10,
        "exfiltration": 8,
        "tool_abuse": 8,
        "prompt_leak": 4,
        "multi_step": 4,
    }
    assert len(load_cases(True)) >= 30
    assert len({c["id"] for c in load_cases()}) == 68
    assert baseline()["asr"] >= 0.6
