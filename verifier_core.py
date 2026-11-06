"""
Core SMTP verification logic: syntax check, MX lookup, one RCPT probe.
No pacing or queueing here — that lives in worker.py.
"""

import random
import smtplib
import ssl
import string

import dns.exception
import dns.resolver
from email_validator import EmailNotValidError, validate_email

VALID = "VALID"
INVALID = "INVALID"
SYNTAX_INVALID = "SYNTAX_INVALID"
NO_MX = "NO_MX"
CATCH_ALL = "CATCH_ALL"
TEMPORARY = "TEMPORARY"
BLOCKED = "BLOCKED"
UNREACHABLE = "UNREACHABLE"

BLOCK_HINTS = ("spamhaus", "blocked", "blacklist", "blocklist", "reputation",
               "policy", "denied", "not allowed", "access denied", "banned")

# Confidence label shown to the user, derived from status.
CONFIDENCE = {
    VALID: "Confirmed",
    INVALID: "Confirmed",
    SYNTAX_INVALID: "Confirmed",
    NO_MX: "Confirmed",
    CATCH_ALL: "Can't tell",
    TEMPORARY: "Can't tell",
    BLOCKED: "Can't tell",
    UNREACHABLE: "Can't tell",
}

OUTLOOK_DOMAINS = {
    "outlook.com", "hotmail.com", "live.com", "msn.com",
    "hotmail.co.uk", "outlook.co.uk", "hotmail.fr", "outlook.fr",
    "hotmail.it", "outlook.it", "hotmail.de", "outlook.de",
    "hotmail.es", "outlook.es", "passport.com",
}


def provider_group(domain):
    """Which pacing lane this domain belongs to. Outlook/Hotmail share one
    lane since they're the same backend; everything else gets its own."""
    d = domain.lower()
    if d in OUTLOOK_DOMAINS or d.endswith(".outlook.com"):
        return "outlook"
    return d


def check_syntax(email):
    try:
        result = validate_email(email, check_deliverability=False)
        return True, result.normalized
    except EmailNotValidError as e:
        return False, str(e)


def get_mx_hosts(domain):
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 10
    try:
        answers = resolver.resolve(domain, "MX")
        records = sorted(answers, key=lambda r: r.preference)
        hosts = [str(r.exchange).rstrip(".") for r in records]
        return [h for h in hosts if h]
    except dns.resolver.NoAnswer:
        try:
            resolver.resolve(domain, "A")
            return [domain]
        except dns.exception.DNSException:
            return []
    except dns.exception.DNSException:
        return []


def _random_local_part():
    return "zz" + "".join(random.choices(string.ascii_lowercase + string.digits, k=14))


def classify_reject(message):
    text = (message or "").lower()
    if any(h in text for h in BLOCK_HINTS):
        return BLOCKED
    return INVALID


def probe(host, email, domain, sender, helo_domain, timeout, known_catchall=None):
    """
    One SMTP session: connect, (maybe) check catch-all, RCPT the real address.
    known_catchall: True/False if already known for this domain, else None
    (meaning: test it now and report back what was found).
    Returns (status, detail, catchall_result_or_None).
    """
    with smtplib.SMTP(host, 25, timeout=timeout, local_hostname=helo_domain) as smtp:
        smtp.ehlo(helo_domain)
        if smtp.has_extn("starttls"):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            smtp.starttls(context=ctx)
            smtp.ehlo(helo_domain)

        code, msg = smtp.mail(sender)
        if code >= 400:
            text = msg.decode(errors="replace")
            status = TEMPORARY if code < 500 else BLOCKED
            return status, f"MAIL FROM rejected ({code}): {text}", None

        code, msg = smtp.rcpt(email)
        text = msg.decode(errors="replace")

        if code in (250, 251):
            catchall_found = known_catchall
            if known_catchall is None:
                fake = f"{_random_local_part()}@{domain}"
                fcode, _ = smtp.rcpt(fake)
                catchall_found = fcode in (250, 251)
            if catchall_found:
                return CATCH_ALL, f"Server accepts any address ({code})", True
            return VALID, f"Accepted ({code})", False

        if 400 <= code < 500:
            return TEMPORARY, f"Temporary failure ({code}): {text}", known_catchall

        return classify_reject(text), f"Rejected ({code}): {text}", known_catchall


def verify(email, sender, helo_domain, timeout, mx_cache_get, mx_cache_set,
           catchall_cache_get):
    """
    Full check for one address, using cached MX hosts and cached catch-all
    knowledge where available. Returns (status, detail, confidence, catchall).
    """
    ok, normalized = check_syntax(email)
    if not ok:
        return SYNTAX_INVALID, normalized, CONFIDENCE[SYNTAX_INVALID], None

    email = normalized
    domain = email.rsplit("@", 1)[1]

    hosts = mx_cache_get(domain)
    if hosts is None:
        hosts = get_mx_hosts(domain)
        mx_cache_set(domain, hosts)
    if not hosts:
        return NO_MX, f"No MX/A records for {domain}", CONFIDENCE[NO_MX], None

    known_catchall = catchall_cache_get(domain)

    last_error = "no hosts tried"
    for host in hosts[:3]:
        try:
            status, detail, catchall = probe(
                host, email, domain, sender, helo_domain, timeout, known_catchall
            )
            return status, detail, CONFIDENCE.get(status, "Can't tell"), catchall
        except (OSError, smtplib.SMTPException) as e:
            last_error = f"{host}: {e}"
            continue

    return UNREACHABLE, last_error, CONFIDENCE[UNREACHABLE], None
