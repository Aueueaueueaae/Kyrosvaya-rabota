import requests


DEFAULT_TIMEOUT_S = 60


def upload_encrypted(
    server_url: str,
    *,
    filename: str,
    mime: str,
    size: int,
    salt_b64: str,
    nonce_b64: str,
    kdf_iterations: int,
    ciphertext: bytes,
) -> dict:
    url = server_url.rstrip("/") + "/api/upload"
    data = {
        "filename": filename,
        "mime": mime,
        "size": str(size),
        "salt_b64": salt_b64,
        "nonce_b64": nonce_b64,
        "kdf_iterations": str(kdf_iterations),
    }
    files = {"ciphertext": ("ciphertext.bin", ciphertext, "application/octet-stream")}
    r = requests.post(url, data=data, files=files, timeout=DEFAULT_TIMEOUT_S)
    r.raise_for_status()
    return r.json()


def list_files(server_url: str) -> list[dict]:
    url = server_url.rstrip("/") + "/api/files"
    r = requests.get(url, timeout=DEFAULT_TIMEOUT_S)
    r.raise_for_status()
    return r.json().get("files", [])


def get_file(server_url: str, file_id: str) -> dict:
    url = server_url.rstrip("/") + f"/api/files/{file_id}"
    r = requests.get(url, timeout=DEFAULT_TIMEOUT_S)
    r.raise_for_status()
    return r.json()


def delete_file(server_url: str, file_id: str) -> None:
    url = server_url.rstrip("/") + f"/api/files/{file_id}"
    r = requests.delete(url, timeout=DEFAULT_TIMEOUT_S)
    r.raise_for_status()

