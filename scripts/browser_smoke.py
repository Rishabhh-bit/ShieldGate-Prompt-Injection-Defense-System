"""Optional browser checks. Install playwright and its Chromium browser first."""

import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

root = Path(__file__).resolve().parents[1]
server = subprocess.Popen(
    [
        sys.executable,
        "-m",
        "uvicorn",
        "shieldgate.api:app",
        "--host",
        "127.0.0.1",
        "--port",
        "8017",
    ],
    cwd=root,
    stdout=subprocess.DEVNULL,
)
try:
    for _ in range(50):
        try:
            urllib.request.urlopen("http://127.0.0.1:8017/health", timeout=1)
            break
        except OSError:
            time.sleep(0.1)
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, executable_path=os.getenv("CHROMIUM_EXECUTABLE"))
        page = browser.new_page(viewport={"width": 1440, "height": 1050})
        errors: list[str] = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.goto("http://127.0.0.1:8017")
        expect(page.locator("#connection")).to_have_text("OFFLINE ENGINE READY")
        page.get_by_role("button", name="Fooled model / blocked tool").click()
        page.locator("#run").click()
        expect(page.locator("#effects")).to_contain_text("Unauthorized action blocked")
        page.locator("#benchmark").click()
        expect(page.locator("#protected")).to_have_text("0.0%", timeout=60000)
        page.get_by_role("button", name="Human approval").click()
        page.locator("#run").click()
        page.get_by_role("button", name="Approve once").click()
        expect(page.locator("#effects")).to_contain_text("1 simulated sends")
        page.locator("#verify").click()
        expect(page.locator("#integrity")).to_contain_text("Verified")
        page.locator("#defense").uncheck()
        page.get_by_role("button", name="MailPilot inbox").click()
        page.locator("#run").click()
        expect(page.locator("#effects")).to_contain_text("1 simulated sends")
        page.set_viewport_size({"width": 390, "height": 844})
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        assert not errors, errors
        browser.close()
        print(
            "PASS: desktop, mobile, blocked tool, approval, baseline, evaluation, audit; no JS errors"
        )
finally:
    server.terminate()
    server.wait(timeout=5)
