from pathlib import Path
import re

root = Path(__file__).resolve().parents[1]
base_path = root / "app" / "templates" / "base.html"
main_path = root / "app" / "main.py"

favicon_block = '''    <title>OpenCase | Repair Workflow Management</title>
    <meta name="description" content="OpenCase is a repair workflow and work order management application built with FastAPI, PostgreSQL, Google OAuth, analytics dashboards, and role-based access control.">
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
    <link rel="icon" type="image/png" sizes="32x32" href="/static/favicon-32x32.png">
    <link rel="icon" type="image/png" sizes="16x16" href="/static/favicon-16x16.png">
    <link rel="apple-touch-icon" href="/static/apple-touch-icon.png">
'''

text = base_path.read_text(encoding="utf-8")
# Remove existing title/meta/favicon/apple-touch-icon lines in head only, then insert clean block before <style>.
head_start = text.find("<head>")
style_pos = text.find("<style>", head_start)
if head_start == -1 or style_pos == -1:
    raise RuntimeError("Could not find <head> and <style> in app/templates/base.html")

head = text[head_start:style_pos]
rest = text[style_pos:]
head = re.sub(r"\s*<title>.*?</title>\s*", "\n", head, flags=re.I | re.S)
head = re.sub(r"\s*<meta\s+name=[\"']description[\"'][^>]*>\s*", "\n", head, flags=re.I)
head = re.sub(r"\s*<link\s+rel=[\"'](?:shortcut icon|icon|apple-touch-icon)[\"'][^>]*>\s*", "\n", head, flags=re.I)
head = re.sub(r"\n{3,}", "\n\n", head).rstrip() + "\n"
text = head + "\n" + favicon_block + rest
base_path.write_text(text, encoding="utf-8")
print("Updated app/templates/base.html")

main = main_path.read_text(encoding="utf-8")
if 'def favicon(' not in main and '@app.get("/favicon.ico"' not in main and "@app.get('/favicon.ico'" not in main:
    anchor = 'app.mount("/static", StaticFiles(directory="app/static"), name="static")'
    route = '''\n\n@app.get("/favicon.ico", include_in_schema=False)\ndef favicon():\n    return FileResponse("app/static/favicon.ico")\n'''
    if anchor in main:
        main = main.replace(anchor, anchor + route, 1)
    else:
        # Fallback: insert after app = FastAPI(...) line/block by placing before middleware setup.
        marker = "app.add_middleware"
        pos = main.find(marker)
        if pos == -1:
            raise RuntimeError("Could not find a safe insertion point in app/main.py")
        main = main[:pos] + route + "\n" + main[pos:]
    main_path.write_text(main, encoding="utf-8")
    print("Updated app/main.py with /favicon.ico route")
else:
    print("app/main.py already has a favicon route")
