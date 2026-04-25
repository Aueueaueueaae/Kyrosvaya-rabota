import os

import base64
import streamlit as st

from api_client import delete_file, get_file, list_files, upload_encrypted
from crypto import decrypt, encrypt


st.set_page_config(page_title="Encrypted Cloud Storage", layout="wide")

st.title("Encrypted Cloud Storage")

server_url_default = os.environ.get("SERVER_URL", "http://localhost:8000")

with st.sidebar:
    st.header("Settings")
    server_url = st.text_input("Server URL", value=server_url_default)
    password = st.text_input("Encryption password", type="password")
    kdf_iterations = st.number_input("PBKDF2 iterations", min_value=10000, max_value=2000000, value=200000, step=10000)

st.markdown(
    "Загружайте только зашифрованные данные. Сервер не хранит пароль и не может расшифровать файлы."
)

if "files" not in st.session_state:
    st.session_state["files"] = []

col1, col2 = st.columns(2)

with col1:
    st.subheader("Upload")
    uploaded = st.file_uploader("Choose file", type=None)
    if st.button("Encrypt & Upload", disabled=uploaded is None):
        if not password:
            st.error("Password is required.")
        else:
            try:
                file_bytes = uploaded.read()
                mime = uploaded.type or "application/octet-stream"
                meta, ciphertext = encrypt(file_bytes, password, iterations=int(kdf_iterations))
                res = upload_encrypted(
                    server_url,
                    filename=uploaded.name,
                    mime=mime,
                    size=len(file_bytes),
                    salt_b64=meta["salt_b64"],
                    nonce_b64=meta["nonce_b64"],
                    kdf_iterations=meta["kdf_iterations"],
                    ciphertext=ciphertext,
                )
                st.success(f"Uploaded: {res.get('filename')}")
                st.session_state["files"] = list_files(server_url)
            except Exception as e:
                st.error(f"Upload failed: {e}")

with col2:
    st.subheader("Files")
    if st.button("Refresh list"):
        try:
            st.session_state["files"] = list_files(server_url)
        except Exception as e:
            st.error(f"Cannot load list: {e}")

    files = st.session_state["files"]
    if files:
        st.dataframe(
            [{"filename": f.get("filename"), "size": f.get("size"), "created_at": f.get("created_at")} for f in files],
            use_container_width=True,
        )
        id_to_name = {f.get("id"): f.get("filename") for f in files if f.get("id")}
        ids = list(id_to_name.keys())
    else:
        ids = []
        id_to_name = {}
        st.info("No files yet.")

st.divider()

col3, col4 = st.columns(2)

with col3:
    st.subheader("Download & Decrypt")
    selected_id = st.selectbox(
        "Select file",
        options=ids,
        format_func=lambda x: id_to_name.get(x, x),
        disabled=not ids,
    )
    if st.button("Decrypt & Download", disabled=not selected_id):
        if not password:
            st.error("Password is required.")
        else:
            try:
                rec = get_file(server_url, selected_id)
                ct = base64.b64decode(rec["ciphertext_b64"])
                plaintext = decrypt(
                    ct,
                    password,
                    salt_b64=rec["salt_b64"],
                    nonce_b64=rec["nonce_b64"],
                    iterations=int(rec["kdf_iterations"]),
                )
                filename = rec.get("filename") or f"decrypted_{selected_id}"
                mime = rec.get("mime") or "application/octet-stream"
                st.download_button(
                    label="Download decrypted file",
                    data=plaintext,
                    file_name=filename,
                    mime=mime,
                )
            except Exception:
                st.error("Decryption failed. Check that the password is correct.")

with col4:
    st.subheader("Delete")
    selected_id_del = st.selectbox(
        "Select file to delete",
        options=ids,
        format_func=lambda x: id_to_name.get(x, x),
        disabled=not ids,
    )
    if st.button("Delete selected", disabled=not selected_id_del):
        try:
            delete_file(server_url, selected_id_del)
            st.success("Deleted.")
            st.session_state["files"] = list_files(server_url)
        except Exception as e:
            st.error(f"Delete failed: {e}")

