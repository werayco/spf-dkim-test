import streamlit as st
from utils import security  # assuming your class is in security.py
import os
import tempfile

st.set_page_config(page_title="Email Security Validator", layout="centered")

st.title("📧 Email Security Validator (SPF, DKIM, DMARC)")

st.markdown("""
Upload an email file (.eml) and provide the IP address and envelope sender.
This tool will validate SPF, DKIM, and DMARC records accordingly.
""")

uploaded_file = st.file_uploader("upload .eml email File", type=["eml"])


ip_address = st.text_input("IP Address (Mail Server)", placeholder="e.g., 198.51.100.1")
envelope_sender = st.text_input("✉️ Envelope Sender (MAIL FROM)", placeholder="e.g., sender@example.com")

if st.button("🔍 Validate Email Security"):
    if not uploaded_file or not ip_address or not envelope_sender:
        st.error("Please provide all inputs.")
    else:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as tmp_file:
            tmp_file.write(uploaded_file.read())
            tmp_path = tmp_file.name

        # Perform checks
        st.subheader("🔒 Results")

        spf_result = security.spfer(envelope_sender, ip_address)
        st.write(f"**SPF Check:** {spf_result}")

        dkim_result = security.verify_dkim(tmp_path)
        st.write(f"**DKIM Check:** {dkim_result}")

        dmarc_result = security.dmarc_validate(tmp_path, ip_address, envelope_sender)
        st.write(f"**DMARC Check:** {dmarc_result}")

        # Cleanup
        os.remove(tmp_path)
