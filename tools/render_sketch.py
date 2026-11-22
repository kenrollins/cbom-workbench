"""Render a journal sketch (SVG) to PNG so it can be looked at: python3 render_sketch.py in.svg [out.png] [width].

Drawn by headless Chromium (Playwright; on the authoring host, the system python3), so the picture is
what a reader's browser shows: the faces are the ones embedded in the SVG, and nothing depends on what
fonts the box has installed. The default width is the notes column's, where small lettering shows."""
import base64
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

src = Path(sys.argv[1])
out = Path(sys.argv[2]) if len(sys.argv) > 2 else src.with_suffix(".png")
width = int(sys.argv[3]) if len(sys.argv) > 3 else 760
data = base64.b64encode(src.read_bytes()).decode()
with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page(viewport={"width": width, "height": 600})
    page.set_content(f'<body style="margin:0;background:#f7f2e8"><img src="data:image/svg+xml;base64,{data}" style="width:{width}px;display:block"></body>')
    page.wait_for_timeout(300)
    page.screenshot(path=str(out), full_page=True)
    browser.close()
print(out, out.stat().st_size, "bytes")
