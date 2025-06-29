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
        try:
            ip_obj = ipaddress.ip_address(sender_ip)
        except ValueError:
            return "FAIL"
            
        for domain, record in spf_records_dict.items():
            if not isinstance(record, str) or not record.startswith("v=spf1"):
                continue
            blocks = SPFResolver.extract_ip_blocks(record)
            for block in blocks:
                if ip_obj in block:
                    return "PASS"
        return "FAIL"

    @staticmethod
    def get_organizational_domain(domain):
        """Extract organizational domain from subdomain"""
        parts = domain.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return domain

    @staticmethod
    def extract_sender_info_from_eml(file_path: str):
        with open(file_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
            
        from_header = msg.get("From", "")
        _, email_addr = parseaddr(from_header)
        
        # Extract domain from Return-Path or From
        return_path = msg.get("Return-Path", "")
        if return_path:
            _, return_email = parseaddr(return_path)
            if return_email and '@' in return_email:
                sender_domain = return_email.split('@')[1].strip('<>')
            else:
                sender_domain = email_addr.split('@')[1] if '@' in email_addr else None
        else:
            sender_domain = email_addr.split('@')[1] if '@' in email_addr else None
            
        # Extract sender IP
        received_headers = msg.get_all('Received', [])
        sender_ip = None
        for header in received_headers:
            ip_match = re.search(r'\[([0-9]{1,3}(?:\.[0-9]{1,3}){3})\]', header)
            if ip_match:
                sender_ip = ip_match.group(1)
                break

        return sender_domain, sender_ip, email_addr
    
    @staticmethod
    def spfer(email: str, ip: str):
        try:
            helo = email.split("@")[1]
            result, explanation = spf.check2(i=ip, s=email, h=helo)
            return result.upper(), explanation
        except Exception as e:
            return "PERMERROR", str(e)
    
    @staticmethod
    def soemail_spf(file_path):
        try:
            sender_domain, ip, email_addr = SPFResolver.extract_sender_info_from_eml(file_path)
            
            if not sender_domain or not ip:
                return {"ip": ip, "domain": sender_domain, "spf_status": "NONE", "error": "Missing domain or IP"}
            
            # Get organizational domain for SPF check
            org_domain = SPFResolver.get_organizational_domain(sender_domain)
            
            # Try custom SPF checker first
            records = SPFResolver.resolve_all_includes(org_domain)
            result = SPFResolver.check_ip_against_spf_blocks(ip, records)
            
            if result == "FAIL":
                # Also check the exact sender domain if different from org domain
                if sender_domain != org_domain:
                    sender_records = SPFResolver.resolve_all_includes(sender_domain)
                    result = SPFResolver.check_ip_against_spf_blocks(ip, sender_records)
                
                if result == "FAIL":
                    # Fall back to pyspf
                    pyspf_result, explanation = SPFResolver.spfer(email=email_addr, ip=ip)
                    return {
                        "ip": ip, 
                        "domain": sender_domain, 
                        "spf_status": pyspf_result,
                        "method": "pyspf",
                        "explanation": explanation
                    }
            
            return {
                "ip": ip, 
                "domain": sender_domain, 
                "spf_status": result,
                "method": "custom"
            }
            
        except Exception as e:
            return {
                "ip": None, 
                "domain": None, 
                "spf_status": "ERROR",
                "error": str(e)
            }


if __name__ == "__main__":
    file_path = r"C:\Users\miztu\Downloads\Graphic Designer at SyncPath Consulting Limited and 12 more graphic designer jobs in Lagos for you!.eml"
    result = SPFResolver.soemail_spf(file_path)
    print(f"\nSPF Check Result:")
    for key, value in result.items():
        print(f"  {key}: {value}")
    
    # Debug: Check SPF record for indeed.com
    print(f"\nDirect SPF record for indeed.com:")
    spf_record = SPFResolver.get_spf_record("indeed.com")
    if spf_record:
        print(f"  {spf_record[:100]}...")
    else:
        print("  Not found")