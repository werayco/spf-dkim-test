import spf
import dkim
import dns.resolver
import email
import email.utils

class security:
    @staticmethod
    def spfer(email:str, ip:str):
        try:
            helo = email.split("@")[1]
            result, _ = spf.check2(i=ip, s=email, h=helo)
            return "PASS" if result == "pass" else "FAIL"
        except Exception as e:
            return "permerror", f"SPF check failed: {e}"
    
    @staticmethod
    def verify_dkim(file_path):
        with open(file_path, "rb") as f:
            email_data = f.read()
        try:
            valid = dkim.verify(email_data)
            return "PASS" if valid else "FAIL"
        except Exception as e:
            return "FAIL"
        
    @staticmethod
    def check_dmarc(domain):
        try:
            query = f"_dmarc.{domain}"
            answers = dns.resolver.resolve(query, 'TXT')
            for rdata in answers:
                txt = ''.join(rdata.strings)
                if txt.lower().startswith("v=dmarc1"):
                    return txt
            return None
        except Exception:
            return None

    @staticmethod
    def dmarc_validate(file_path, ip, mail_from):
        with open(file_path, "rb") as f:
            raw = f.read()
        msg = email.message_from_bytes(raw)

        from_addr = email.utils.parseaddr(msg.get("From", ""))[1]
        from_domain = from_addr.split("@")[-1] if "@" in from_addr else ""
        if not from_domain:
            return "FAIL"

        spf_result = security.spfer(mail_from, ip)
        spf_aligned = mail_from.lower().endswith("@" + from_domain.lower())

        dkim_result = security.verify_dkim(file_path)
        dkim_aligned = dkim_result == "PASS" 

        dmarc_record = security.check_dmarc(from_domain)
        policy = "none"
        if dmarc_record:
            for part in dmarc_record.split(";"):
                part = part.strip()
                if part.startswith("p="):
                    policy = part.split("=")[1].strip()

        dmarc_pass = (
            (spf_result == "PASS" and spf_aligned)
            or (dkim_result == "PASS" and dkim_aligned)
        )

        if dmarc_pass:
            return "PASS"
        else:
            return f"FAIL ({policy})"
