import dkim
import dns.resolver
import email
import email.utils
from email import policy
from email.parser import BytesParser
import re
from datetime import datetime
import time

class security:
    @staticmethod
    def verify_dkim(file_path):
        """Verify DKIM with proper DNS configuration and return all signature results."""
        # Configure DNS resolver
        dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
        dns.resolver.default_resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1']
        
        with open(file_path, "rb") as f:
            email_data = f.read()
        
        try:
            # Verify the email
            valid = dkim.verify(email_data)
            
            # Parse to get domain information
            msg = email.message_from_bytes(email_data)
            dkim_headers = msg.get_all("DKIM-Signature", [])
            
            # Collect all domains from DKIM signatures
            domains = []
            for header in dkim_headers:
                parts = header.split(";")
                for part in parts:
                    part = part.strip()
                    if part.startswith("d="):
                        domain = part.split("=", 1)[1].strip()
                        domains.append(domain)
            
            # Return the overall result and all domains
            # If any signature is valid, dkim.verify returns True
            return ("PASS" if valid else "FAIL", domains if domains else None)
            
        except Exception as e:
            # Log the error for debugging
            print(f"DKIM verification error: {e}")
            return ("FAIL", None)
    
    @staticmethod
    def verify_dkim_detailed(file_path):
        """Get detailed DKIM verification status for each signature."""
        # Configure DNS resolver
        dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
        dns.resolver.default_resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1']
        
        with open(file_path, "rb") as f:
            email_data = f.read()
        
        msg = email.message_from_bytes(email_data)
        dkim_headers = msg.get_all("DKIM-Signature", [])
        
        results = []
        current_time = time.time()
        
        for idx, header in enumerate(dkim_headers, 1):
            # Parse signature fields
            fields = {}
            sig_text = re.sub(r'\s+', ' ', header)
            for match in re.finditer(r'(\w+)=([^;]+)(?:;|$)', sig_text):
                fields[match.group(1)] = match.group(2).strip()
            
            domain = fields.get('d', 'unknown')
            selector = fields.get('s', 'unknown')
            
            # Check expiration
            is_expired = False
            if 'x' in fields:
                expires = int(fields['x'])
                is_expired = current_time > expires
            
            results.append({
                'index': idx,
                'domain': domain,
                'selector': selector,
                'is_expired': is_expired,
                'has_expiration': 'x' in fields
            })
        
        # Overall verification
        try:
            valid = dkim.verify(email_data)
            overall_status = "PASS" if valid else "FAIL"
        except Exception as e:
            overall_status = "FAIL"
            print(f"DKIM verification error: {e}")
        
        return overall_status, results

    @staticmethod
    def check_dmarc(domain):
        """Check DMARC record for a domain."""
        try:
            # Configure DNS resolver
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1']
            
            query = f"_dmarc.{domain}"
            answers = resolver.resolve(query, 'TXT')
            for rdata in answers:
                txt = ''.join([s.decode() if isinstance(s, bytes) else s for s in rdata.strings])
                if txt.lower().startswith("v=dmarc1"):
                    return txt
            return None
        except Exception as e:
            print(f"DMARC lookup error for {domain}: {e}")
            return None

    @staticmethod
    def dmarc_validate(file_path, ip, mail_from, spfResult: str):
        """Validate DMARC with improved DKIM handling."""
        with open(file_path, "rb") as f:
            raw = f.read()
        msg = email.message_from_bytes(raw)

        from_addr = email.utils.parseaddr(msg.get("From", ""))[1]
        from_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else ""
        if not from_domain:
            return {"result": "FAIL", "reason": "Invalid From domain"}

        spf_result = spfResult
        spf_domain = mail_from.split("@")[-1].lower() if mail_from and "@" in mail_from else ""

        # Default DMARC values
        aspf_mode = "r"
        adkim_mode = "r"
        policy = "none"

        dmarc_record = security.check_dmarc(from_domain)
        if dmarc_record:
            for part in dmarc_record.split(";"):
                part = part.strip()
                if part.startswith("p="):
                    policy = part.split("=")[1].strip()
                elif part.startswith("aspf="):
                    aspf_mode = part.split("=")[1].strip().lower()
                elif part.startswith("adkim="):
                    adkim_mode = part.split("=")[1].strip().lower()

        # SPF alignment
        if aspf_mode == "s":
            spf_aligned = spf_domain == from_domain
        else:
            spf_aligned = spf_domain == from_domain or spf_domain.endswith("." + from_domain)

        # DKIM result and alignment
        dkim_result, dkim_domains = security.verify_dkim(file_path)
        
        # Check DKIM alignment for all signatures
        dkim_aligned = False
        if dkim_result == "PASS" and dkim_domains:
            for dkim_domain in dkim_domains:
                dkim_domain = dkim_domain.lower()
                if adkim_mode == "s":
                    if dkim_domain == from_domain:
                        dkim_aligned = True
                        break
                else:
                    if dkim_domain == from_domain or dkim_domain.endswith("." + from_domain):
                        dkim_aligned = True
                        break

        # DMARC logic
        passed = (
            (spf_result == "PASS" and spf_aligned) or
            (dkim_result == "PASS" and dkim_aligned)
        )

        reason = []
        if spf_result != "PASS":
            reason.append("SPF failed")
        elif not spf_aligned:
            reason.append("SPF not aligned")
        if dkim_result != "PASS":
            reason.append("DKIM failed")
        elif not dkim_aligned:
            reason.append("DKIM not aligned")

        return {
            "result": "PASS" if passed else "FAIL",
            "reason": "; ".join(reason) if reason else "All passed",
            "policy": {
                "domain": from_domain,
                "p": policy,
                "aspf": aspf_mode,
                "adkim": adkim_mode
            },
            "alignment": {
                "spf_aligned": spf_aligned,
                "dkim_aligned": dkim_aligned
            },
            "auth": {
                "spf": spf_result,
                "dkim": dkim_result
            },
            "dkim_domains": dkim_domains  # Added for debugging
        }

    @staticmethod
    def parse_dkim_dates(eml_file_path):
        """Parse DKIM signature dates and expiration information."""
        with open(eml_file_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)

        dkim_headers = msg.get_all('DKIM-Signature')
        
        if not dkim_headers:
            return "❌ No DKIM-Signature found in the email.", 0, []
        
        signatures_count = len(dkim_headers)
        signatures_info = []
        
        for idx, dkim_header in enumerate(dkim_headers, 1):
            t_match = re.search(r'\bt=(\d+)', dkim_header)
            x_match = re.search(r'\bx=(\d+)', dkim_header)
            
            d_match = re.search(r'\bd=([^;]+)', dkim_header)
            domain = d_match.group(1).strip() if d_match else "Unknown"
            
            sig_info = {
                'index': idx,
                'domain': domain
            }
            
            if t_match:
                t_value = int(t_match.group(1))
                t_date = datetime.utcfromtimestamp(t_value).strftime('%A, %Y-%m-%d %H:%M:%S UTC')
                sig_info['signed_on'] = t_date
            else:
                sig_info['signed_on'] = "Not specified"
            
            if x_match:
                x_value = int(x_match.group(1))
                x_date = datetime.utcfromtimestamp(x_value).strftime('%A, %Y-%m-%d %H:%M:%S UTC')
                sig_info['expires_on'] = x_date
                
                # Check if expired
                if time.time() > x_value:
                    sig_info['status'] = "EXPIRED"
                else:
                    sig_info['status'] = "Valid"
            else:
                sig_info['expires_on'] = "Not specified (signature does not expire)"
                sig_info['status'] = "Valid (no expiration)"
            
            signatures_info.append(sig_info)
        
        summary_lines = [f"📧 Found {signatures_count} DKIM signature(s):"]
        
        for sig in signatures_info:
            summary_lines.append(f"\n Signature {sig['index']} (Domain: {sig['domain']}):")
            summary_lines.append(f"   Signed on: {sig['signed_on']}")
            summary_lines.append(f"   Expires on: {sig['expires_on']}")
            summary_lines.append(f"   Status: {sig.get('status', 'Unknown')}")
        
        summary = "\n".join(summary_lines)
        
        return summary, signatures_count, signatures_info

# eml_path = r"C:\Users\miztu\Downloads\The Tuesday Drop - 06.24.25.eml"  
# file_path = r"C:\Users\miztu\Downloads\About your registration using Github (3).eml"
# with open(file_path, "rb") as f:
#     email_data = f.read()
#     valid = dkim.verify(email_data, debuglog=print)
#     print(valid)