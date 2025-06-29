import dns.resolver
import ipaddress
import re
from typing import Dict, List, Tuple, Set, Optional, Union
import email
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
import spf


class SPFResolver:
    @staticmethod
    def get_spf_record(domain):
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                if hasattr(rdata, "strings"):
                    txt = ''.join([s.decode() if isinstance(s, bytes) else s for s in rdata.strings])
                else:
                    txt = rdata.to_text().strip('"')
                if txt.startswith('v=spf1'):
                    return txt
        except Exception:
            return None
        return None

    @staticmethod
    def extract_includes(spf_record):
        includes = re.findall(r'include:([^\s]+)', spf_record)
        redirects = re.findall(r'redirect=([^\s]+)', spf_record)
        return includes + redirects

    @staticmethod
    def extract_ip_blocks(spf_record):
        matches = re.findall(r'(ip4|ip6):([^\s]+)', spf_record)
        blocks = []
        for _, cidr in matches:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                blocks.append(net)
            except ValueError:
                continue
        return blocks

    @staticmethod
    def resolve_all_includes(domain, depth=0, visited=None):
        if visited is None:
            visited = set()
        domain = domain.lower().strip()
        if domain in visited or depth > 20:
            return {}
        visited.add(domain)
        resolved = {}
        spf = SPFResolver.get_spf_record(domain)
        if not spf or not spf.startswith("v=spf1"):
            resolved[domain] = f"⚠️ Invalid or missing SPF"
            return resolved
        resolved[domain] = spf
        includes = SPFResolver.extract_includes(spf)
        for inc in includes:
            if inc not in visited:
                nested = SPFResolver.resolve_all_includes(inc, depth + 1, visited)
                resolved.update(nested)
        return resolved

    @staticmethod
    def check_ip_against_spf_blocks(sender_ip, spf_records_dict):
        ip_obj = ipaddress.ip_address(sender_ip)
        for record in spf_records_dict.values():
            if not isinstance(record, str) or not record.startswith("v=spf1"):
                continue
            blocks = SPFResolver.extract_ip_blocks(record)
            for block in blocks:
                if ip_obj in block:
                    return "PASS"
        return "FAIL"
    

    @staticmethod
    def extract_sender_info_from_eml(file_path: str) -> Optional[Tuple[str, str, str]]:
        with open(file_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)

        # Extract sender email
        sender_email = None
        return_path = msg.get('Return-Path')
        if return_path:
            email_match = re.search(r'<(.+?)>', return_path)
            if email_match:
                sender_email = email_match.group(1)
            else:
                sender_email = return_path.strip()

        # Extract domain from Received-SPF
        spf_headers = msg.get_all('Received-SPF')
        sender_domain = None
        if spf_headers:
            for spf_header in spf_headers:
                # Try common SPF patterns
                match = re.search(r'domain of .*?@([^\s;]+)', spf_header)
                if not match:
                    match = re.search(r'\bpostmaster@([^\s\)]+)', spf_header)
                if match:
                    sender_domain = match.group(1)
                    break

        # Extract IP address from Received headers
        received_headers = msg.get_all('Received', [])
        sender_ip = None
        for header in received_headers:
            ip_match = re.search(r'\[([0-9]{1,3}(?:\.[0-9]{1,3}){3})\]', header)
            if ip_match:
                sender_ip = ip_match.group(1)
                break

        if sender_email and sender_domain and sender_ip:
            return sender_email, sender_domain, sender_ip

        return None
    
    @staticmethod
    def spfer(email: str, ip: str):
        try:
            helo = email.split("@")[1]
            result, _ = spf.check2(i=ip, s=email, h=helo)
            return result.upper()  
        except Exception as e:
            return "PERMERROR"
    
    @staticmethod
    def soemail_spf(file_path):
        try:
            root_domain, ip, email = SPFResolver.extract_sender_info_from_eml(file_path)
            records = SPFResolver.resolve_all_includes(root_domain)
            result = SPFResolver.check_ip_against_spf_blocks(ip, records)
            if result == "FAIL":
                print(f"custom spf checker failed, moving to pyspf")
                email = SPFResolver.extract_valid_ips(file_path=file_path)
                pyspf_result = SPFResolver.spfer(email=email, ip=ip)
                return {"ip":ip, "domain":root_domain, "spf_status":pyspf_result}
            else:
                print(f"using custom made spf checker")
                return {"ip":ip, "domain":root_domain, "spf_status":result}
        except Exception as e:
                return {f"error":"an error occured,{e}"}
        
    @staticmethod 
    def extract_valid_ips(file_path, public_only=True):
        with open(file_path, 'rb') as f:
            raw_email = f.read()

        msg = email.message_from_bytes(raw_email)
        from_header = msg.get("From", "")
        name, email_addr = parseaddr(from_header)
        return  email_addr

if __name__ == "__main__":
    file_path = r"C:\Users\miztu\Downloads\💥 Find opportunities_ DappRadar's Gambling Narrative Page.eml"
    email_addr = SPFResolver.extract_valid_ips(file_path)
    root_domain, ip , email = SPFResolver.extract_sender_info_from_eml(file_path)
    print(root_domain)
    print(email_addr)
    x = SPFResolver.soemail_spf(file_path)
    print(x)


    # result =SPFResolver.soemail_spf(file_path)
    # print(result)

