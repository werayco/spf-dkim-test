import email
from email import policy
from email.parser import BytesParser
import re
from datetime import datetime

def parse_dkim_dates(eml_file_path):
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
        else:
            sig_info['expires_on'] = "Not specified (signature does not expire)"
        
        signatures_info.append(sig_info)
    
    summary_lines = [f"📧 Found {signatures_count} DKIM signature(s):"]
    
    for sig in signatures_info:
        summary_lines.append(f"\n Signature {sig['index']} (Domain: {sig['domain']}):")
        summary_lines.append(f"   Signed on: {sig['signed_on']}")
        summary_lines.append(f"   Expires on: {sig['expires_on']}")
    
    summary = "\n".join(summary_lines)
    
    return summary, signatures_count, signatures_info

eml_path = r"C:\Users\miztu\Downloads\The Tuesday Drop - 06.24.25.eml"  

if __name__ == "__main__":
    summary, signatures_count, signatures_info = parse_dkim_dates(eml_path)
    print(summary)
    print(signatures_count)
