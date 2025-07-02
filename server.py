import streamlit as st
from utils import security  # assuming your class is in security.py
import os
import tempfile
import email
import re
import ipaddress
from email.utils import parseaddr
from soemail.dmarc_dkim import security
from soemail.so_spf import SPFResolver

# from soemail_spf import SPFResolver

def extract_valid_ips(file_path):
    with open(file_path, 'rb') as f:
        raw_email = f.read()

    msg = email.message_from_bytes(raw_email)
    from_header = msg.get("From", "")
    name, email_addr = parseaddr(from_header)

    return  email_addr

st.set_page_config(page_title="Email Security Validator", layout="centered")

st.title("📧 Email Security Validator (SPF, DKIM, DMARC)")

st.markdown("""
Upload an email file (.eml) alone.
This tool will validate SPF, DKIM, and DMARC records accordingly.
""")

uploaded_file = st.file_uploader("upload .eml email File", type=["eml"])


if st.button("🔍 Validate Email Security"):
    if not uploaded_file:
        st.error("Please provide all inputs.")
    else:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as tmp_file:
            tmp_file.write(uploaded_file.read())
            tmp_path = tmp_file.name

        st.subheader("🔒 Results")
        result = SPFResolver.soemail_spf(tmp_path)
        st.write(f"**SPF Check:** {result}")

        dkim_result, _ = security.verify_dkim(tmp_path)
        summary, signatures_count, signatures_info = security.parse_dkim_dates(tmp_path)
        st.write(f"***Number of DKIM signature found:*** {signatures_count}")
        st.write(f"**Details:** {signatures_info}")
        st.write(f"**DKIM Check:** {dkim_result}")


        dmarc_result = security.dmarc_validate(tmp_path, result.get('ip'), result.get('email_address'), spfResult=result.get('spf_status'))

        st.write(f"**DMARC Check:** {dmarc_result}")

        # Cleanup
        os.remove(tmp_path)
