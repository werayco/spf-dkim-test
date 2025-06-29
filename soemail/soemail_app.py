from dmarc_dkim import security
from so_spf import SPFResolver

file_path = r"C:\Users\miztu\Downloads\[TEST] Wallet verification reminder.eml"
result = SPFResolver.soemail_spf(file_path)
print(result)
# root_domain, ip, email = 
dkim_result, _ = security.verify_dkim(file_path)
print(dkim_result)
dmarc_result = security.dmarc_validate(file_path, result.get('ip'), result.get('email_address'), spfResult=result.get('spf_status'))
print(dmarc_result)