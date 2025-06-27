import spf
import dkim
import dns.resolver
import email
import email.utils

class security:
    @staticmethod
    def spfer(email: str, ip: str):
        try:
            helo = email.split("@")[1]
            result, _ = spf.check2(i=ip, s=email, h=helo)
            return result.upper()  # e.g., "PASS", "FAIL", "SOFTFAIL", etc.
        except Exception as e:
            return "PERMERROR"

    @staticmethod
    def verify_dkim(file_path):
        with open(file_path, "rb") as f:
            email_data = f.read()
        try:
            valid = dkim.verify(email_data)

            # Extract d= domain from DKIM-Signature header
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
    def dmarc_validate(file_path, ip, mail_from):
        with open(file_path, "rb") as f:
            raw = f.read()
        msg = email.message_from_bytes(raw)

        from_addr = email.utils.parseaddr(msg.get("From", ""))[1]
        from_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else ""
        if not from_domain:
            return "FAIL (invalid From domain)"

        spf_result = security.spfer(mail_from, ip)
        spf_domain = mail_from.split("@")[-1].lower()
        
        # Default to relaxed alignment
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

        # SPF alignment check
        if aspf_mode == "s": #
            spf_aligned = spf_domain == from_domain
        else:  # relaxed
            spf_aligned = spf_domain == from_domain or spf_domain.endswith("." + from_domain)

        # DKIM result and alignment
        # Assuming this returns a tuple: ("PASS", "signed_domain.com")
        dkim_result, dkim_domain = security.verify_dkim(file_path)
        dkim_domain = dkim_domain.lower() if dkim_domain else ""

        if dkim_result == "PASS":
            if adkim_mode == "s":
                dkim_aligned = dkim_domain == from_domain
            else:
                dkim_aligned = dkim_domain == from_domain or dkim_domain.endswith("." + from_domain)
        else:
            dkim_aligned = False

        # Final DMARC pass decision
        dmarc_pass = (
            (spf_result == "PASS" and spf_aligned)
            or (dkim_result == "PASS" and dkim_aligned)
        )

        return "PASS" if dmarc_pass else f"FAIL ({policy})"
