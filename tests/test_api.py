from fastapi.testclient import TestClient

from shieldgate.api import create_app


def client(tmp_path):
    app = create_app(tmp_path / "audit.jsonl")
    c = TestClient(app)
    token = c.get("/config").json()["token"]
    c.headers["X-ShieldGate-Token"] = token
    return c


def test_endpoints_and_operator_boundary(tmp_path):
    c = client(tmp_path)
    assert c.get("/").status_code == 200
    assert c.get("/health").json()["status"] == "ok"
    assert c.post("/chat", json={}, headers={"X-ShieldGate-Token": "bad"}).status_code == 403
    assert c.post("/chat", json={}, headers={"Origin": "https://evil.test"}).status_code == 403
    assert c.get("/health", headers={"Host": "evil.test"}).status_code == 400
    assert (
        c.post("/chat", json={"external": [{"source": "system", "text": "x"}]}).status_code == 422
    )
    assert c.post("/chat", json={"role": "admin"}).status_code == 422
    assert c.post("/chat", json={"scenario": "unknown"}).status_code == 400
    assert c.post("/chat", json={"session_id": "deadbeef"}).status_code == 404
    response = c.post("/chat", json={"scenario": "fooled"}).json()
    assert "block" in response["decisions"] and response["simulated_sends"] == 0
    sid = response["session_id"]
    assert c.get(f"/sessions/{sid}/trace").json()
    assert c.get("/sessions/missing/trace").status_code == 404
    assert c.post("/chat", json={"session_id": sid, "defense": False}).status_code == 409
    assert c.post("/chat", json={"session_id": sid, "model": "robust"}).status_code == 409
    assert c.post("/chat", json={"session_id": sid, "message": "Thanks"}).status_code == 200
    assert c.get("/audit/verify").json()["valid"]


def test_approval_and_report_endpoints(tmp_path):
    c = client(tmp_path)
    assert c.get("/approvals").json() == []
    assert c.post("/chat", json={"scenario": "approval"}).json()["pending"] == 1
    a = c.get("/approvals").json()[0]
    approved = c.post("/approvals/" + a["id"], json={"approve": True})
    assert approved.status_code == 200 and approved.json()["simulated_sends"] == 1
    assert c.post("/approvals/" + a["id"], json={"approve": True}).status_code == 409
    assert c.post("/approvals/unknown", json={"approve": True}).status_code == 404
    assert (
        c.post("/chat", json={"scenario": "image"}).json()["response"]
        == "![status]([link removed])"
    )
    assert (
        c.post("/chat", json={"scenario": "mailpilot", "defense": False}).json()["simulated_sends"]
        == 1
    )
    assert c.post("/chat", json={"model": "robust", "message": "hi"}).status_code == 200
    report = c.post("/redteam/run", json={}).json()
    assert len(report["ablations"]) == 8 and report["summary"]["protected_asr"] <= 0.05
