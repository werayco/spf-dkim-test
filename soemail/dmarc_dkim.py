import spf
import dkim
import dns.resolver
import email
import email.utils
from .so_spf import SPFResolver

class security:
    @staticmethod
    def verify_dkim(file_path):
        with open(file_path, "rb") as f:
            email_data = f.read()
        try:
            valid = dkim.verify(email_data)

            msg = email.message_from_bytes(email_data)
            dkim_headers = msg.get_all("DKIM-Signature", [])
            for header in dkim_headers:
                parts = header.split(";")
                for part in parts:
                    part = part.strip()
                    if part.startswith("d="):
                        dkim_domain = part.split("=", 1)[1].strip()
                        return ("PASS" if valid else "FAIL", dkim_domain)

            return ("PASS" if valid else "FAIL", None)
        except Exception:
            return ("FAIL", None)

        
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
    def dmarc_validate(file_path, ip, mail_from, spfResult: str):
        with open(file_path, "rb") as f:
            raw = f.read()
        msg = email.message_from_bytes(raw)

        from_addr = email.utils.parseaddr(msg.get("From", ""))[1]
        from_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else ""
        if not from_domain:
            return {"result": "FAIL", "reason": "Invalid From domain"}

        # spf_result = security.spfer(mail_from, ip)
        # spf_result = SPFResolver.soemail_spf(file_path).get("spf_status")
        spf_result = spfResult
        spf_domain = mail_from.split("@")[-1].lower()

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
        dkim_result, dkim_domain = security.verify_dkim(file_path)
        dkim_domain = dkim_domain.lower() if dkim_domain else ""
        if dkim_result == "PASS":
            if adkim_mode == "s":
                dkim_aligned = dkim_domain == from_domain
            else:
                dkim_aligned = dkim_domain == from_domain or dkim_domain.endswith("." + from_domain)
        else:
            dkim_aligned = False

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
            }
        }

