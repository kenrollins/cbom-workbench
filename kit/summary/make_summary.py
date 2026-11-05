import sys, pymupdf as fitz
ver = sys.argv[1]
css = open("summary.css").read()
html = open("summary.html").read().replace("{ver}", ver)
story = fitz.Story(html=html, user_css=css, archive=fitz.Archive("."))
writer = fitz.DocumentWriter("cbom-workbench-summary.pdf"); rect = fitz.paper_rect("letter"); where = rect + (38, 30, -38, -30)
more = True
while more:
    dev = writer.begin_page(rect); more, _ = story.place(where); story.draw(dev); writer.end_page()
writer.close()
doc = fitz.open("cbom-workbench-summary.pdf"); print("pages", len(doc))
doc.save("cbom-workbench-summary.min.pdf", garbage=4, deflate=True, deflate_images=True)
for i, pg in enumerate(doc): pg.get_pixmap(dpi=80).save(f"page{i+1}.png")
