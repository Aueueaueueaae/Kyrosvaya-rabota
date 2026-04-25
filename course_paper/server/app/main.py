import base64
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile


app = FastAPI(title="Encrypted Storage Server")


def storage_dir() -> Path:
    d = Path(os.environ.get("STORAGE_DIR", "/data/storage"))
    d.mkdir(parents=True, exist_ok=True)
    return d


def file_dir(file_id: str) -> Path:
    return storage_dir() / file_id


def meta_path(file_id: str) -> Path:
    return file_dir(file_id) / "meta.json"


def ciphertext_path(file_id: str) -> Path:
    return file_dir(file_id) / "ciphertext.bin"


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_meta(file_id: str) -> dict:
    p = meta_path(file_id)
    if not p.exists():
        raise HTTPException(status_code=404, detail="File not found")
    return json.loads(p.read_text(encoding="utf-8"))


@app.get("/api/health")
def health():
    return {"ok": True}


@app.post("/api/upload")
async def upload(
    ciphertext: UploadFile = File(...),
    filename: str = Form(...),
    mime: str = Form(...),
    size: int = Form(...),
    salt_b64: str = Form(...),
    nonce_b64: str = Form(...),
    kdf_iterations: int = Form(...),
):
    file_id = str(uuid.uuid4())
    d = file_dir(file_id)
    d.mkdir(parents=True, exist_ok=True)

    ct_bytes = await ciphertext.read()
    if not ct_bytes:
        raise HTTPException(status_code=400, detail="Empty ciphertext")

    meta = {
        "id": file_id,
        "filename": filename,
        "mime": mime,
        "size": size,
        "created_at": iso_now(),
        "salt_b64": salt_b64,
        "nonce_b64": nonce_b64,
        "kdf_iterations": kdf_iterations,
    }

    meta_path(file_id).write_text(json.dumps(meta, ensure_ascii=False), encoding="utf-8")
    ciphertext_path(file_id).write_bytes(ct_bytes)

    return {
        "id": file_id,
        "filename": filename,
        "mime": mime,
        "size": size,
        "created_at": meta["created_at"],
    }


@app.get("/api/files")
def list_files():
    base = storage_dir()
    out = []
    for sub in base.iterdir():
        if not sub.is_dir():
            continue
        mp = sub / "meta.json"
        if not mp.exists():
            continue
        try:
            meta = json.loads(mp.read_text(encoding="utf-8"))
        except Exception:
            continue
        out.append(
            {
                "id": meta.get("id", sub.name),
                "filename": meta.get("filename"),
                "mime": meta.get("mime"),
                "size": meta.get("size"),
                "created_at": meta.get("created_at"),
            }
        )
    out.sort(key=lambda x: x.get("created_at") or "", reverse=True)
    return {"files": out}


@app.get("/api/files/{file_id}")
def get_file(file_id: str):
    meta = load_meta(file_id)
    ct_p = ciphertext_path(file_id)
    if not ct_p.exists():
        raise HTTPException(status_code=404, detail="Ciphertext not found")
    ct_bytes = ct_p.read_bytes()

    return {
        "id": meta["id"],
        "filename": meta["filename"],
        "mime": meta["mime"],
        "size": meta["size"],
        "created_at": meta["created_at"],
        "salt_b64": meta["salt_b64"],
        "nonce_b64": meta["nonce_b64"],
        "kdf_iterations": meta["kdf_iterations"],
        "ciphertext_b64": base64.b64encode(ct_bytes).decode("ascii"),
    }


@app.delete("/api/files/{file_id}")
def delete_file(file_id: str):
    d = file_dir(file_id)
    if not d.exists():
        raise HTTPException(status_code=404, detail="File not found")
    mp = meta_path(file_id)
    cp = ciphertext_path(file_id)
    if mp.exists():
        mp.unlink()
    if cp.exists():
        cp.unlink()
    try:
        d.rmdir()
    except OSError:
        pass
    return {"ok": True}

