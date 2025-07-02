import email
from email import policy
from email.parser import BytesParser
import re
from datetime import datetime

def parse_dkim_dates(eml_file_path):
    with open(eml_file_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    dkim_header = msg['DKIM-Signature']
    print(dkim_header)
    if not dkim_header:
        return "❌ No DKIM-Signature found in the email."

    t_match = re.search(r'\bt=(\d+)', dkim_header)
    x_match = re.search(r'\bx=(\d+)', dkim_header)

    if not t_match:
        return "❌ No signing time (t=) found in DKIM-Signature."

    t_value = int(t_match.group(1))
    t_date = datetime.utcfromtimestamp(t_value).strftime('%A, %Y-%m-%d %H:%M:%S UTC')

    if x_match:
        x_value = int(x_match.group(1))
        x_date = datetime.utcfromtimestamp(x_value).strftime('%A, %Y-%m-%d %H:%M:%S UTC')
    else:
        x_date = "Not specified (signature does not expire)"

    return f"Signed on: {t_date}\nExpires on: {x_date}"

# Example usage
eml_path = r"C:\Users\miztu\Downloads\Don't let your rewards slip away!.eml"  # replace with your actual .eml file path
result = parse_dkim_dates(eml_path)
print(result)
