import streamlit as st
from utils import security  # assuming your class is in security.py
import os
import tempfile
import email
import re
import ipaddress

def extract_valid_ips(file_path, public_only=True):
    with open(file_path, 'rb') as f:
        raw_email = f.read()

    msg = email.message_from_bytes(raw_email)
    received_headers = msg.get_all("Received", [])
    ip_candidate_pattern = r'(?:(?:\d{1,3}\.){3}\d{1,3})|(?:[a-fA-F0-9:]+:+)+[a-fA-F0-9]+'

    valid_ips = []
    for header in received_headers:
        candidates = re.findall(ip_candidate_pattern, header)
        for ip in candidates:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if not public_only or ip_obj.is_global:
                    valid_ips.append(str(ip_obj))
            except ValueError:
                continue 
    return list(set(valid_ips)) 

st.set_page_config(page_title="Email Security Validator", layout="centered")

st.title("📧 Email Security Validator (SPF, DKIM, DMARC)")

st.markdown("""
Upload an email file (.eml) and provide the IP address and envelope sender.
This tool will validate SPF, DKIM, and DMARC records accordingly.
""")

uploaded_file = st.file_uploader("upload .eml email File", type=["eml"])

envelope_sender = st.text_input("✉️ Envelope Sender (MAIL FROM)", placeholder="e.g., sender@example.com")

if st.button("🔍 Validate Email Security"):
    if not uploaded_file or not envelope_sender:
        st.error("Please provide all inputs.")
    else:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as tmp_file:
            tmp_file.write(uploaded_file.read())
            tmp_path = tmp_file.name

        # Perform checks
        st.subheader("🔒 Results")
        ip_address = extract_valid_ips(file_path=tmp_path)[0]
        spf_result = security.spfer(envelope_sender, ip_address)
        st.write(f"**SPF Check:** {spf_result}")

        dkim_result = security.verify_dkim(tmp_path)
        st.write(f"**DKIM Check:** {dkim_result}")

        dmarc_result = security.dmarc_validate(tmp_path, ip_address, envelope_sender)
        st.write(f"**DMARC Check:** {dmarc_result}")

        # Cleanup
        os.remove(tmp_path)
