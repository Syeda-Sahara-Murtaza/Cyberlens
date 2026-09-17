
import os
import re
import base64
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
import whois


# ============================================================
# SECRET HELPER
# ============================================================

def get_secret(name):
    value = os.getenv(name)

    if not value:
        raise RuntimeError(
            f"Required secret '{name}' is not configured."
        )

    return value


# ============================================================
# RESULT HELPER
# ============================================================

def make_result(source, success=True, data=None, error=None):
    return {
        "source": source,
        "success": success,
        "data": data or {},
        "error": error
    }


# ============================================================
# INPUT HELPERS
# ============================================================

def extract_domain(target):
    target = target.strip()

    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    parsed = urlparse(target)

    domain = parsed.hostname

    if domain:
        domain = domain.lower().strip(".")

    return domain


def is_ip(value):
    try:
        ipaddress.ip_address(value.strip())
        return True
    except Exception:
        return False


def is_url(value):
    value = value.strip().lower()
    return value.startswith("http://") or value.startswith("https://")


# ============================================================
# DATE HELPERS
# ============================================================

def normalize_date(value):

    if value is None:
        return None

    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)

        return value

    if isinstance(value, list) and value:
        return normalize_date(value[0])

    if isinstance(value, tuple) and value:
        return normalize_date(value[0])

    return None


def calculate_domain_age(created_date):

    created = normalize_date(created_date)

    if not created:
        return None

    try:
        now = datetime.now(timezone.utc)

        age_days = (now - created).days

        if age_days < 0:
            return 0

        return age_days

    except Exception:
        return None


# ============================================================
# VIRUSTOTAL
# ============================================================

def get_virustotal(target):

    api_key = get_secret("VIRUSTOTAL_API_KEY")

    headers = {
        "x-apikey": api_key,
        "Accept": "application/json"
    }

    target = target.strip()

    try:

        # ----------------------------------------------------
        # IP ADDRESS
        # ----------------------------------------------------

        if is_ip(target):

            endpoint = (
                "https://www.virustotal.com/api/v3/ip_addresses/"
                + target
            )

            response = requests.get(
                endpoint,
                headers=headers,
                timeout=20
            )

            if response.status_code != 200:

                return make_result(
                    "VirusTotal",
                    False,
                    error=f"VirusTotal HTTP {response.status_code}"
                )

            payload = response.json()

            attributes = (
                payload
                .get("data", {})
                .get("attributes", {})
            )

            stats = attributes.get(
                "last_analysis_stats",
                {}
            )

            return make_result(
                "VirusTotal",
                True,
                {
                    "type": "ip",
                    "target": target,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "reputation": attributes.get("reputation"),
                    "country": attributes.get("country"),
                    "asn": attributes.get("asn"),
                    "as_owner": attributes.get("as_owner")
                }
            )


        # ----------------------------------------------------
        # DOMAIN
        # ----------------------------------------------------

        domain = extract_domain(target)

        if not domain:

            return make_result(
                "VirusTotal",
                False,
                error="Could not extract domain."
            )

        # ----------------------------------------------------
        # EXACT URL LOOKUP
        # ----------------------------------------------------

        if is_url(target):

            try:

                encoded_url = (
                    base64.urlsafe_b64encode(
                        target.encode()
                    )
                    .decode()
                    .rstrip("=")
                )

                url_endpoint = (
                    "https://www.virustotal.com/api/v3/urls/"
                    + encoded_url
                )

                url_response = requests.get(
                    url_endpoint,
                    headers=headers,
                    timeout=20
                )

                if url_response.status_code == 200:

                    url_payload = url_response.json()

                    url_attributes = (
                        url_payload
                        .get("data", {})
                        .get("attributes", {})
                    )

                    url_stats = url_attributes.get(
                        "last_analysis_stats",
                        {}
                    )

                    return make_result(
                        "VirusTotal",
                        True,
                        {
                            "type": "url",
                            "target": target,
                            "domain": domain,
                            "malicious": url_stats.get(
                                "malicious", 0
                            ),
                            "suspicious": url_stats.get(
                                "suspicious", 0
                            ),
                            "harmless": url_stats.get(
                                "harmless", 0
                            ),
                            "undetected": url_stats.get(
                                "undetected", 0
                            ),
                            "reputation": url_attributes.get(
                                "reputation"
                            ),
                            "exact_url_checked": True
                        }
                    )

            except Exception:
                pass

        # ----------------------------------------------------
        # DOMAIN LOOKUP
        # ----------------------------------------------------

        endpoint = (
            "https://www.virustotal.com/api/v3/domains/"
            + domain
        )

        response = requests.get(
            endpoint,
            headers=headers,
            timeout=20
        )

        if response.status_code != 200:

            return make_result(
                "VirusTotal",
                False,
                error=f"VirusTotal HTTP {response.status_code}"
            )

        payload = response.json()

        attributes = (
            payload
            .get("data", {})
            .get("attributes", {})
        )

        stats = attributes.get(
            "last_analysis_stats",
            {}
        )

        return make_result(
            "VirusTotal",
            True,
            {
                "type": "domain",
                "target": target,
                "domain": domain,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "reputation": attributes.get("reputation"),
                "creation_date": attributes.get(
                    "creation_date"
                ),
                "last_analysis_date": attributes.get(
                    "last_analysis_date"
                ),
                "exact_url_checked": False
            }
        )

    except requests.exceptions.Timeout:

        return make_result(
            "VirusTotal",
            False,
            error="VirusTotal request timed out."
        )

    except Exception as e:

        return make_result(
            "VirusTotal",
            False,
            error=str(e)
        )


# ============================================================
# WHOIS
# ============================================================

def get_whois(target):

    try:

        domain = extract_domain(target)

        if not domain:

            return make_result(
                "WHOIS",
                False,
                error="Could not extract domain."
            )

        # WHOIS does not work directly with IPs in the
        # same way as normal domain lookups.
        if is_ip(domain):

            return make_result(
                "WHOIS",
                True,
                {
                    "domain": domain,
                    "available": False,
                    "message": "WHOIS domain lookup not applicable to IP."
                }
            )

        info = whois.whois(domain)

        creation_date = normalize_date(
            getattr(info, "creation_date", None)
        )

        expiration_date = normalize_date(
            getattr(info, "expiration_date", None)
        )

        updated_date = normalize_date(
            getattr(info, "updated_date", None)
        )

        registrar = getattr(
            info,
            "registrar",
            None
        )

        nameservers = getattr(
            info,
            "name_servers",
            None
        )

        domain_age_days = calculate_domain_age(
            creation_date
        )

        return make_result(
            "WHOIS",
            True,
            {
                "domain": domain,
                "available": True,
                "registrar": registrar,
                "creation_date": (
                    creation_date.isoformat()
                    if creation_date
                    else None
                ),
                "expiration_date": (
                    expiration_date.isoformat()
                    if expiration_date
                    else None
                ),
                "updated_date": (
                    updated_date.isoformat()
                    if updated_date
                    else None
                ),
                "domain_age_days": domain_age_days,
                "nameservers": nameservers
            }
        )

    except Exception as e:

        return make_result(
            "WHOIS",
            False,
            error=str(e)
        )


# ============================================================
# SOURCE REGISTRY
#
# To add a future source:
#
# def get_new_source(target):
#     ...
#
# SOURCES["New Source"] = get_new_source
# ============================================================

SOURCES = {
    "VirusTotal": get_virustotal,
    "WHOIS": get_whois
}


# ============================================================
# RUN ALL SOURCES
# ============================================================

def run_sources(target):

    results = {}

    for name, function in SOURCES.items():

        try:
            results[name] = function(target)

        except Exception as e:

            results[name] = make_result(
                name,
                False,
                error=str(e)
            )

    return results
