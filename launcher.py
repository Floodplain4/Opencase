import os
import time
import webbrowser
import threading
from pathlib import Path

import uvicorn


def app_data_dir() -> Path:
    base = os.getenv("APPDATA") or str(Path.home())
    path = Path(base) / "OpenCaseTracker"
    path.mkdir(parents=True, exist_ok=True)
    return path


def run_server():
    os.environ["OPENCASE_DATA_DIR"] = str(app_data_dir())
    os.environ["LOCAL_MODE"] = "true"
    print("LOCAL_MODE =", os.environ.get("LOCAL_MODE"))

    from app.main import app

    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8000,
        reload=False,
        workers=1,
        log_level="warning",
    )

if __name__ == "__main__":
    thread = threading.Thread(target=run_server, daemon=True)
    thread.start()

    time.sleep(2)
    webbrowser.open("http://127.0.0.1:8000")

    while True:
        time.sleep(1)