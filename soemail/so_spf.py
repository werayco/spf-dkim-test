import dns.resolver
import ipaddress
import re
from typing import Dict, List, Tuple, Set, Optional
import email
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
import spf
import time

resolver = dns.resolver.Resolver()
resolver.nameservers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
resolver.timeout = 3.0
resolver.lifetime = 5.0

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
    def extract_sender_domain_from_eml(file_path: str) -> Optional[Tuple[str, str, str]]:
        with open(file_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)

        from_header = msg.get("From", "")
        _, email_addr = parseaddr(from_header)

        sender_domain = None

        # 1. Received-SPF header
        spf_headers = msg.get_all('Received-SPF')
        if spf_headers:
            for spf_header in spf_headers:
                match = re.search(r'domain of .*?@([^\s;]+)', spf_header)
                if match:
                    sender_domain = match.group(1)
                    break

        # 2. Return-Path fallback
        if not sender_domain:
            return_path = msg.get("Return-Path")
            if return_path:
                _, return_email = parseaddr(return_path)
                if return_email and "@" in return_email:
                    sender_domain = return_email.split("@")[1]

        # 3. From fallback
        if not sender_domain and email_addr and "@" in email_addr:
            sender_domain = email_addr.split("@")[1]

        sender_ip = None

        # 1. From Received headers
        received_headers = msg.get_all('Received', [])
        for header in received_headers:
            ip_match = re.search(r'\[([0-9]{1,3}(?:\.[0-9]{1,3}){3})\]', header)
            if ip_match:
                sender_ip = ip_match.group(1)
                break

        # 2. X-Originating-IP
        if not sender_ip:
            xoip = msg.get("X-Originating-IP")
            if xoip:
                ip_match = re.search(r'\[?([0-9]{1,3}(?:\.[0-9]{1,3}){3})\]?', xoip)
                if ip_match:
                    sender_ip = ip_match.group(1)

        # 3. X-Forwarded-For
        if not sender_ip:
            xff = msg.get("X-Forwarded-For")
            if xff:
                ip_match = re.search(r'([0-9]{1,3}(?:\.[0-9]{1,3}){3})', xff)
                if ip_match:
                    sender_ip = ip_match.group(1)

        if sender_domain and sender_ip:
            return sender_domain.strip(), sender_ip.strip(), email_addr.strip()

        return None

    @staticmethod
    def spfer(email: str, ip: str, retries=5, delay=3):
        try:
            for attempt in range(retries):
                helo = email.split("@")[1]
                result, explanation = spf.check2(i=ip, s=email, h=helo)
                if result.upper() != "TEMPERROR":
                    return result.upper(), explanation
                print(f"Retry {attempt + 1} due to TEMPERROR...")
                time.sleep(delay)
            return "TEMPERROR", "Retries exhausted"
        except Exception as e:
            return "PERMERROR", str(e)

    @staticmethod
    def soemail_spf(file_path):
        extracted = SPFResolver.extract_sender_domain_from_eml(file_path)
        if extracted is None:
            return {
                "ip": None,
                "domain": None,
                "spf_status": "NONE",
                "error": "Could not extract sender domain or IP from email headers"
            }

        root_domain, ip, email = extracted

        try:
            records = SPFResolver.resolve_all_includes(root_domain)
            result = SPFResolver.check_ip_against_spf_blocks(ip, records)

            if result == "FAIL":
                print("Custom SPF checker failed, moving to pyspf")
                pyspf_result, _ = SPFResolver.spfer(email=email, ip=ip)
                return {"ip": ip, "domain": root_domain, "spf_status": pyspf_result, "email_address": email}
            else:
                print("Using custom SPF checker")
                return {"ip": ip, "domain": root_domain, "spf_status": result, "email_address": email}

        except Exception as e:
            return {
                "ip": ip,
                "domain": root_domain,
                "spf_status": "ERROR",
                "error": str(e)
            }
 
if __name__ == "__main__":
    file_path = r"C:\Users\miztu\Downloads\Activate your Wattpad account.eml"
    # file_path = r"C:\Users\miztu\Downloads\Graphic Designer at SyncPath Consulting Limited and 12 more graphic designer jobs in Lagos for you!.eml"

    result = SPFResolver.soemail_spf(file_path).get("spf_status")
    print(result)

