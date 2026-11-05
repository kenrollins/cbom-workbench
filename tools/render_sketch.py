"""Render a journal sketch (SVG) to PNG so it can be looked at: python render_sketch.py in.svg [out.png] [width].
cairosvg over the box's libcairo; the book's faces must be installed for fontconfig (~/.fonts, fc-cache)."""
import sys
from pathlib import Path
import cairosvg

src = Path(sys.argv[1])
out = Path(sys.argv[2]) if len(sys.argv) > 2 else src.with_suffix(".png")
width = int(sys.argv[3]) if len(sys.argv) > 3 else 1200
cairosvg.svg2png(url=str(src), write_to=str(out), output_width=width)
print(out, out.stat().st_size, "bytes")
