"""
Streamlit App Lock
- Single-file Streamlit app that acts as an app-lock (protects the protected UI behind a password).
- Uses PBKDF2-HMAC-SHA256 for password hashing with a random salt.
- Stores vault data in vault.json (salt, hashed password, failed attempts, lock_until).
- No external crypto libraries required (uses Python stdlib).
- Auto-locks after inactivity (configurable).
"""

import streamlit as st
import os
import json
import time
import hashlib
import secrets
from datetime import datetime, timedelta

VAULT_FILE = "vault.json"
PBKDF2_ITERATIONS = 200_000  # high iteration count for security
AUTO_LOCK_SECONDS = 300  # auto-lock after 5 minutes of inactivity
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 60  # temporary lockout after too many failed attempts


# --------------------------
# Vault persistence helpers
# --------------------------
def load_vault():
    if not os.path.exists(VAULT_FILE):
        return {}
    try:
        with open(VAULT_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_vault(data: dict):
    with open(VAULT_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f)


# --------------------------
# Password hashing helpers
# --------------------------
def hash_password(password: str, salt: bytes) -> str:
    """Return hex-encoded pbkdf2-hmac-sha256 derived key."""
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )
    return dk.hex()


def verify_password(password: str, salt_hex: str, expected_hash_hex: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    return secrets.compare_digest(hash_password(password, salt), expected_hash_hex)


def generate_salt() -> bytes:
    return secrets.token_bytes(16)


# --------------------------
# Vault operations
# --------------------------
def initialize_vault(password: str):
    salt = generate_salt()
    vault = {
        "salt": salt.hex(),
        "password_hash": hash_password(password, salt),
        "failed_attempts": 0,
        "lock_until": None,
        "created_at": datetime.utcnow().isoformat(),
    }
    save_vault(vault)
    return vault


def set_new_password(old_password: str, new_password: str) -> (bool, str):
    vault = load_vault()
    if not vault:
        return False, "Vault not initialized."
    if not verify_password(old_password, vault["salt"], vault["password_hash"]):
        return False, "Current password incorrect."
    salt = generate_salt()
    vault["salt"] = salt.hex()
    vault["password_hash"] = hash_password(new_password, salt)
    vault["failed_attempts"] = 0
    vault["lock_until"] = None
    save_vault(vault)
    return True, "Password changed."


def register_failed_attempt(vault):
    vault["failed_attempts"] = vault.get("failed_attempts", 0) + 1
    if vault["failed_attempts"] >= MAX_FAILED_ATTEMPTS:
        lock_until = datetime.utcnow() + timedelta(seconds=LOCKOUT_SECONDS)
        vault["lock_until"] = lock_until.isoformat()
    save_vault(vault)


def reset_failed_attempts(vault):
    vault["failed_attempts"] = 0
    vault["lock_until"] = None
    save_vault(vault)


# --------------------------
# Session state helpers
# --------------------------
def ensure_session_state():
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False
    if "last_active" not in st.session_state:
        st.session_state.last_active = time.time()
    if "username" not in st.session_state:
        st.session_state.username = "owner"


def autolock_check():
    """Auto-lock if inactivity exceeds AUTO_LOCK_SECONDS."""
    now = time.time()
    if st.session_state.logged_in and (now - st.session_state.last_active) > AUTO_LOCK_SECONDS:
        st.session_state.logged_in = False
        st.experimental_rerun()


# --------------------------
# UI pieces
# --------------------------
def show_login():
    st.title("🔒 App Lock — Login")
    vault = load_vault()
    if not vault:
        st.info("No master password set. Please create one.")
        return show_setup()

    # check lockout
    lock_until = vault.get("lock_until")
    if lock_until:
        lock_time = datetime.fromisoformat(lock_until)
        if datetime.utcnow() < lock_time:
            remaining = (lock_time - datetime.utcnow()).total_seconds()
            st.error(f"Too many failed attempts. Try again in {int(remaining)} seconds.")
            return

    password = st.text_input("Enter master password", type="password")
    if st.button("Unlock"):
        if verify_password(password, vault["salt"], vault["password_hash"]):
            reset_failed_attempts(vault)
            st.session_state.logged_in = True
            st.session_state.last_active = time.time()
            st.success("Unlocked — welcome!")
            st.experimental_rerun()
        else:
            register_failed_attempt(vault)
            remaining_tries = max(0, MAX_FAILED_ATTEMPTS - vault.get("failed_attempts", 0))
            if remaining_tries == 0:
                st.error("Too many failed attempts. Locked temporarily.")
            else:
                st.error(f"Incorrect password. {remaining_tries} attempt(s) left.")


def show_setup():
    st.title("🔐 Set Master Password")
    st.write("Create a secure master password to protect the app.")
    password = st.text_input("New password", type="password")
    password2 = st.text_input("Confirm password", type="password")
    if st.button("Create Master Password"):
        if not password or not password2:
            st.error("Please enter and confirm the password.")
            return
        if password != password2:
            st.error("Passwords do not match.")
            return
        initialize_vault(password)
        st.success("Master password created. Please log in.")
        st.experimental_rerun()


def show_protected_area():
    st.title("🔓 Protected Area")
    st.write("This content is protected by the master password. You're viewing it because you're unlocked.")
    # Example protected content - you can replace this with whatever you want to protect
    st.markdown(
        """
        - Secret note 1: The quick brown fox jumps over the lazy dog.
        - Secret note 2: Replace this section with your real protected content.
        """
    )
    st.write("---")
    st.write("Session controls:")
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("Lock now"):
            st.session_state.logged_in = False
            st.success("Locked.")
            st.experimental_rerun()
    with col2:
        if st.button("Refresh last active"):
            st.session_state.last_active = time.time()
            st.info("Activity refreshed.")
    with col3:
        if st.button("Delete vault (reset app)"):
            if st.button("Confirm delete vault (double-click)"):
                try:
                    os.remove(VAULT_FILE)
                except Exception:
                    pass
                st.session_state.logged_in = False
                st.success("Vault deleted. App reset. Please reload to set a new password.")
                st.experimental_rerun()

    st.write("---")
    st.subheader("Change master password")
    with st.form("change_pw_form"):
        current = st.text_input("Current password", type="password")
        newpw = st.text_input("New password", type="password")
        newpw2 = st.text_input("Confirm new password", type="password")
        submitted = st.form_submit_button("Change password")
        if submitted:
            if not current or not newpw or not newpw2:
                st.error("Fill all fields.")
            elif newpw != newpw2:
                st.error("New passwords do not match.")
            else:
                ok, msg = set_new_password(current, newpw)
                if ok:
                    st.success(msg)
                    # keep user logged out to force re-login with new password
                    st.session_state.logged_in = False
                    st.experimental_rerun()
                else:
                    st.error(msg)

    st.write("---")
    st.caption("Note: Vault file is stored locally as 'vault.json'. Keep that file private.")


# --------------------------
# App entrypoint
# --------------------------
def main():
    st.set_page_config(page_title="App Lock", page_icon="🔒", layout="centered")
    ensure_session_state()

    # Force autolock if inactive
    autolock_check()

    vault = load_vault()
    if not st.session_state.logged_in:
        # If no vault exists, show setup flow
        if not vault:
            show_setup()
            return
        else:
            show_login()
            return
    else:
        # logged in -> show protected content
        st.session_state.last_active = time.time()
        show_protected_area()


if __name__ == "__main__":
    main()
