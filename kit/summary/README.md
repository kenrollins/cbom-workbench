# The two-page summary for demo day

`summary.html` and `summary.css` are the two pages; `workflow.html` is the workflow diagram as SVG;
`make_summary.py` renders the PDF with PyMuPDF (`pymupdf.Story`), the box's own fonts and two images
beside it: `overview.jpg` (the front page, `/`, cropped to 1920×1000) and `score-q.png` (the answer-key chart, matplotlib)
and `workflow3-q.png` (`workflow3.html` rendered at 3200×740 by a headless browser, quantized).
Fonts go beside it as `garamond.ttf`, `inter.ttf`, `mono.ttf`. Every number in the text was read from
the box on 2026-11-05 and is on its ledger; change them only from a new measurement.

    python make_summary.py <build>    # writes cbom-workbench-summary.min.pdf, two pages, Letter
