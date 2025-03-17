import dkim
import re
import dns.resolver
import ipaddress
import dkim
import streamlit as st

resolver = dns.resolver.Resolver()
resolver.nameservers = ["8.8.8.8", "8.8.4.4"]

def domain_splitter(email):
    return email.split("@")[1]

def get_spf_record(domain):
    try:
        answers = resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt_record = rdata.to_text().strip('"')
            if txt_record.startswith("v=spf1"):
                return txt_record
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return None

def parse_spf_record(spf_record):
    if not spf_record:
        return None
    return {
        "ip4": re.findall(r'ip4:([\d\.\/]+)', spf_record),
        "include": re.findall(r'include:([\w\.\-]+)', spf_record),
        "all": re.search(r'(\+|-|~|\?)all', spf_record)
    }

def validate_ip_in_cidr(sender_ip, cidr_list):
    sender_ip_obj = ipaddress.ip_address(sender_ip)
    for cidr in cidr_list:
        if sender_ip_obj in ipaddress.ip_network(cidr, strict=False):
            return True
    return False

def validate_sender_ip(sender_ip, domain, checked_domains=None):
    if checked_domains is None:
        checked_domains = set()
    if domain in checked_domains:
        return "Loop detected (possible SPF misconfiguration)"
    checked_domains.add(domain)

    spf_record = get_spf_record(domain)
    if not spf_record:
        return "No SPF record found"

    parsed_spf = parse_spf_record(spf_record)

    if sender_ip in parsed_spf["ip4"] or validate_ip_in_cidr(sender_ip, parsed_spf["ip4"]):
        return "Authorized"

    for included_domain in parsed_spf["include"]:
        included_result = validate_sender_ip(sender_ip, included_domain, checked_domains)
        if "Authorized" in included_result:
            return "Authorized (via include)"

    return "Rejected" if parsed_spf["all"] and parsed_spf["all"].group(1) == "-" else "Neutral"

def verify_dkim(file_path):
    with open(file_path, "rb") as f:
        email_data = f.read()
    try:
        return dkim.verify(email_data)
    except Exception:
        return False

def get_dmarc_record(domain):
    dmarc_domain = f"_dmarc.{domain}"
    try:
        answers = resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            txt_record = rdata.to_text().strip('"')
            if txt_record.startswith("v=DMARC1"):
                return txt_record
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return None

def parse_dmarc_record(dmarc_record):
    if not dmarc_record:
        return {"policy": "none", "rua": None}
    policy_match = re.search(r"p=(none|quarantine|reject)", dmarc_record)
    rua_match = re.search(r"rua=mailto:([\w\.\-@]+)", dmarc_record)
    return {"policy": policy_match.group(1) if policy_match else "none", "rua": rua_match.group(1) if rua_match else None}

def evaluate_email(email, sender_ip, eml_path):
    domain = domain_splitter(email)
    spf_result = validate_sender_ip(sender_ip, domain)
    dmarc_record = get_dmarc_record(domain)
    dmarc_info = parse_dmarc_record(dmarc_record)
    dkim_result = verify_dkim(file_path=eml_path)

    spf_passed = "Authorized" in spf_result
    dkim_passed = dkim_result

    if dmarc_info["policy"] == "reject" and not (spf_passed or dkim_passed):
        final_result = "Email Rejected (DMARC Policy Enforced)"
    elif dmarc_info["policy"] == "quarantine" and not (spf_passed or dkim_passed):
        final_result = "Email Quarantined (DMARC Policy Enforced)"
    else:
        final_result = "Email Passed DMARC Verification"

    return {
        "SPF Check": spf_result,
        "DKIM Check": "Valid" if dkim_result else "Invalid",
        "DMARC Policy": dmarc_info["policy"],
        "DMARC Reporting Email": dmarc_info["rua"],
        "Final Result": final_result
    }

resolver = dns.resolver.Resolver()
resolver.nameservers = ["8.8.8.8", "8.8.4.4"]

def domain_splitter(email):
    return email.split("@")[1]

def get_spf_record(domain):
    try:
        answers = resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt_record = rdata.to_text().strip('"')
            if txt_record.startswith("v=spf1"):
                return txt_record
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return None

def parse_spf_record(spf_record):
    if not spf_record:
        return None
    return {
        "ip4": re.findall(r'ip4:([\d\.\/]+)', spf_record),
        "include": re.findall(r'include:([\w\.\-]+)', spf_record),
        "all": re.search(r'(\+|-|~|\?)all', spf_record)
    }

def validate_ip_in_cidr(sender_ip, cidr_list):
    sender_ip_obj = ipaddress.ip_address(sender_ip.strip())  # Trim spaces
    for cidr in cidr_list:
        if sender_ip_obj in ipaddress.ip_network(cidr, strict=False):
            return True
    return False

def validate_sender_ip(sender_ip, domain, checked_domains=None):
    sender_ip = sender_ip.strip()  
    if checked_domains is None:
        checked_domains = set()
    if domain in checked_domains:
        return "Loop detected (possible SPF misconfiguration)"
    checked_domains.add(domain)

    spf_record = get_spf_record(domain)
    if not spf_record:
        return "No SPF record found"

    parsed_spf = parse_spf_record(spf_record)

    if sender_ip in parsed_spf["ip4"] or validate_ip_in_cidr(sender_ip, parsed_spf["ip4"]):
        return "Authorized"

    for included_domain in parsed_spf["include"]:
        included_result = validate_sender_ip(sender_ip, included_domain, checked_domains)
        if "Authorized" in included_result:
            return "Authorized (via include)"

    return "Rejected" if parsed_spf["all"] and parsed_spf["all"].group(1) == "-" else "Neutral"


def verify_dkim(file_path):
    with open(file_path, "rb") as f:
        email_data = f.read()
    try:
        return dkim.verify(email_data)
    except Exception:
        return False

def get_dmarc_record(domain):
    dmarc_domain = f"_dmarc.{domain}"
    try:
        answers = resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            txt_record = rdata.to_text().strip('"')
            if txt_record.startswith("v=DMARC1"):
                return txt_record
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return None

def parse_dmarc_record(dmarc_record):
    if not dmarc_record:
        return {"policy": "none", "rua": None}
    policy_match = re.search(r"p=(none|quarantine|reject)", dmarc_record)
    rua_match = re.search(r"rua=mailto:([\w\.\-@]+)", dmarc_record)
    return {"policy": policy_match.group(1) if policy_match else "none", "rua": rua_match.group(1) if rua_match else None}

def evaluate_email(email, sender_ip, eml_path):
    domain = domain_splitter(email)
    spf_result = validate_sender_ip(sender_ip, domain)
    dmarc_record = get_dmarc_record(domain)
    dmarc_info = parse_dmarc_record(dmarc_record)
    dkim_result = verify_dkim(file_path=eml_path)

    spf_passed = "Authorized" in spf_result
    dkim_passed = dkim_result

    if dmarc_info["policy"] == "reject" and not (spf_passed or dkim_passed):
        final_result = "Email Rejected (DMARC Policy Enforced)"
    elif dmarc_info["policy"] == "quarantine" and not (spf_passed or dkim_passed):
        final_result = "Email Quarantined (DMARC Policy Enforced)"
    else:
        final_result = "Email Passed DMARC Verification"

    return {
        "SPF Check": spf_result,
        "DKIM Check": "Valid" if dkim_result else "Invalid",
        "DMARC Policy": dmarc_info["policy"],
        "DMARC Reporting Email": dmarc_info["rua"],
        "Final Result": final_result
    }

# Streamlit UI
st.title("Email Authentication Checker")

email_address = st.text_input("Enter Email Address", "noreply@github.com")
sender_ip = st.text_input("Enter Sender IP", "192.30.252.203")
uploaded_file = st.file_uploader("Upload .eml file", type="eml")

if uploaded_file is not None:
    with open("temp.eml", "wb") as f:
        f.write(uploaded_file.getbuffer())
    
    results = evaluate_email(email_address, sender_ip, "temp.eml")
    
    st.subheader("Results")
    st.write(f"**SPF Check:** {results['SPF Check']}")
    st.write(f"**DKIM Check:** {results['DKIM Check']}")
    st.write(f"**DMARC Policy:** {results['DMARC Policy']}")
    st.write(f"**DMARC Reporting Email:** {results['DMARC Reporting Email']}")
    st.write(f"**Final Result:** {results['Final Result']}")
