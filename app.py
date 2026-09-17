
# ================================================================
# 🛡️ CYBERLENSE - COMPLETE ONE-CELL GOOGLE COLAB SETUP
# ================================================================
# AI        : Groq
# Sources   : VirusTotal + WHOIS
# Frontend  : Streamlit
# Tunnel    : ngrok
# Secrets   : Google Colab Secrets
# ================================================================

# ------------------------------------------------
# 1. INSTALL REQUIRED PACKAGES
# ------------------------------------------------

import sys
import subprocess
import os
import time
import requests
# import streamlit as st

print("📦 Installing required packages...")

subprocess.run(
    [
        sys.executable,
        "-m",
        "pip",
        "install",
        "-q",
        "streamlit",
        "requests",
        "python-whois",
        "pyngrok"
    ],
    check=True
)

print("✓ Packages installed")


# ------------------------------------------------
# 2. LOAD GOOGLE COLAB SECRETS
# ------------------------------------------------

print("\n🔐 Loading secrets...")

try:
    from google.colab import userdata

    VIRUSTOTAL_API_KEY = userdata.get("VIRUSTOTAL_API_KEY")
    GROQ_API_KEY = userdata.get("GROQ_API_KEY")
    NGROK_AUTH_TOKEN = userdata.get("NGROK_AUTH_TOKEN")

except Exception as e:
    raise RuntimeError(
        "\n❌ Could not load Google Colab Secrets.\n\n"
        "Go to Colab → Secrets and create these exact names:\n"
        "1. VIRUSTOTAL_API_KEY\n"
        "2. GROQ_API_KEY\n"
        "3. NGROK_AUTH_TOKEN\n"
    )

if not VIRUSTOTAL_API_KEY:
    raise RuntimeError("❌ VIRUSTOTAL_API_KEY is missing.")

if not GROQ_API_KEY:
    raise RuntimeError("❌ GROQ_API_KEY is missing.")

if not NGROK_AUTH_TOKEN:
    raise RuntimeError("❌ NGROK_AUTH_TOKEN is missing.")

os.environ["VIRUSTOTAL_API_KEY"] = VIRUSTOTAL_API_KEY
os.environ["GROQ_API_KEY"] = GROQ_API_KEY
os.environ["NGROK_AUTH_TOKEN"] = NGROK_AUTH_TOKEN

print("✓ VIRUSTOTAL_API_KEY loaded")
print("✓ GROQ_API_KEY loaded")
print("✓ NGROK_AUTH_TOKEN loaded")


# ================================================================
# 3. CREATE sources.py
# ================================================================

sources_code = r'''
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
'''

with open("sources.py", "w", encoding="utf-8") as f:
    f.write(sources_code)

print("✓ sources.py created")


# ================================================================
# 4. CREATE app.py
# ================================================================

app_code = r'''
import os
import json
import re
import ipaddress
import requests
import streamlit as st

from sources import (
    run_sources,
    is_ip,
    is_url,
    extract_domain
)


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="Cyberlense",
    page_icon="🛡️",
    layout="wide"
)


# ============================================================
# CSS
# ============================================================

st.markdown(
    """
    <style>

    .main {
        background-color: #0b1020;
    }

    .block-container {
        max-width: 1100px;
        padding-top: 2rem;
    }

    .title {
        font-size: 3rem;
        font-weight: 800;
        text-align: center;
        margin-bottom: 0.3rem;
    }

    .subtitle {
        text-align: center;
        opacity: 0.8;
        margin-bottom: 2rem;
    }

    .safe {
        padding: 22px;
        border-radius: 15px;
        text-align: center;
        background: rgba(0, 180, 80, 0.15);
        border: 1px solid rgba(0, 220, 100, 0.35);
    }

    .suspicious {
        padding: 22px;
        border-radius: 15px;
        text-align: center;
        background: rgba(255, 190, 0, 0.15);
        border: 1px solid rgba(255, 210, 0, 0.35);
    }

    .dangerous {
        padding: 22px;
        border-radius: 15px;
        text-align: center;
        background: rgba(255, 50, 50, 0.15);
        border: 1px solid rgba(255, 70, 70, 0.35);
    }

    .metric-box {
        padding: 18px;
        border-radius: 12px;
        background: rgba(255,255,255,0.05);
        text-align: center;
        margin-bottom: 10px;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# ============================================================
# HEADER
# ============================================================

st.markdown(
    '<div class="title">🛡️ Cyberlense</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">'
    'Intelligent IP, Domain & URL Security Scanner'
    '</div>',
    unsafe_allow_html=True
)


# ============================================================
# VALIDATION
# ============================================================

def validate_target(target):

    target = target.strip()

    if not target:
        return False, "Please enter an IP address, domain, or URL."

    # IP
    if is_ip(target):
        return True, "Valid IP address"

    # URL
    if is_url(target):

        try:
            domain = extract_domain(target)

            if domain:
                return True, "Valid URL"

        except Exception:
            pass

        return False, "Invalid URL."

    # DOMAIN
    domain_pattern = (
        r"^(?=.{1,253}$)"
        r"(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9-]{0,61}"
        r"[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,63}$"
    )

    if re.match(domain_pattern, target):

        return True, "Valid domain"

    return False, (
        "Enter a valid IP address, domain, or URL."
    )


# ============================================================
# GROQ MODEL DISCOVERY
# ============================================================

def get_groq_models(api_key):

    endpoint = "https://api.groq.com/openai/v1/models"

    headers = {
        "Authorization": f"Bearer {api_key}"
    }

    response = requests.get(
        endpoint,
        headers=headers,
        timeout=20
    )

    if response.status_code == 401:
        raise RuntimeError(
            "Groq API key is invalid or expired."
        )

    if response.status_code == 429:
        raise RuntimeError(
            "Groq API rate limit reached."
        )

    if response.status_code != 200:
        raise RuntimeError(
            f"Groq model discovery failed: "
            f"HTTP {response.status_code}"
        )

    payload = response.json()

    return [
        item.get("id")
        for item in payload.get("data", [])
        if item.get("id")
    ]


# ============================================================
# CHOOSE BEST AVAILABLE MODEL
# ============================================================

def choose_model(api_key):

    preferred_models = [
        "llama-3.1-8b-instant",
        "openai/gpt-oss-20b",
        "openai/gpt-oss-120b",
        "llama-3.3-70b-versatile",
        "qwen/qwen3-32b",
        "qwen/qwen3-14b"
    ]

    try:

        available = get_groq_models(api_key)

        for model in preferred_models:

            if model in available:
                return model

        # Generic fallback:
        # choose an available model that looks suitable
        for model in available:

            lower = model.lower()

            if (
                "llama" in lower
                or "gpt-oss" in lower
                or "qwen" in lower
            ):
                return model

        if available:
            return available[0]

        raise RuntimeError(
            "No Groq models are available for this API key."
        )

    except Exception:
        # Keep preferred fallback.
        # Actual API call below will provide the real error.
        return "llama-3.1-8b-instant"


# ============================================================
# DETERMINISTIC SECURITY ANALYSIS
# ============================================================

def calculate_base_risk(source_results):

    vt = source_results.get(
        "VirusTotal",
        {}
    )

    whois_result = source_results.get(
        "WHOIS",
        {}
    )

    vt_data = vt.get("data", {}) if vt.get("success") else {}
    whois_data = (
        whois_result.get("data", {})
        if whois_result.get("success")
        else {}
    )

    malicious = int(
        vt_data.get("malicious", 0) or 0
    )

    suspicious = int(
        vt_data.get("suspicious", 0) or 0
    )

    harmless = int(
        vt_data.get("harmless", 0) or 0
    )

    undetected = int(
        vt_data.get("undetected", 0) or 0
    )

    risk = 10
    flags = []

    # --------------------------------------------------------
    # VirusTotal malicious detections
    # --------------------------------------------------------

    if malicious == 0:
        risk = 10

    elif malicious == 1:
        # ONE isolated detection should NOT automatically
        # become DANGEROUS.
        risk = 45

        flags.append(
            "One isolated malicious detection requires review."
        )

    elif malicious <= 3:

        risk = 65

        flags.append(
            f"{malicious} malicious detections were reported."
        )

    else:

        risk = 85

        flags.append(
            f"{malicious} malicious detections were reported."
        )

    # --------------------------------------------------------
    # Suspicious detections
    # --------------------------------------------------------

    if suspicious >= 1:

        risk += min(
            suspicious * 5,
            20
        )

        flags.append(
            f"{suspicious} suspicious detections were reported."
        )

    # --------------------------------------------------------
    # WHOIS / DOMAIN AGE
    # --------------------------------------------------------

    age_days = whois_data.get(
        "domain_age_days"
    )

    if age_days is not None:

        if age_days < 30:

            risk += 15

            flags.append(
                "Domain appears very recently registered."
            )

        elif age_days < 180:

            risk += 8

            flags.append(
                "Domain is relatively new."
            )

        elif age_days > 3650:

            # Old domain slightly reduces uncertainty,
            # but does NOT override malicious evidence.
            risk -= 5

    else:

        if whois_result.get("success") is False:

            flags.append(
                "WHOIS information could not be verified."
            )

    # --------------------------------------------------------
    # No malicious / suspicious detections
    # --------------------------------------------------------

    if malicious == 0 and suspicious == 0:

        risk = min(
            risk,
            20
        )

        if harmless > 0:

            flags.append(
                f"{harmless} VirusTotal engines marked it harmless."
            )

    # --------------------------------------------------------
    # Clamp
    # --------------------------------------------------------

    risk = max(
        0,
        min(
            100,
            risk
        )
    )

    # --------------------------------------------------------
    # Deterministic verdict
    # --------------------------------------------------------

    if risk <= 25:

        verdict = "SAFE"

    elif risk <= 69:

        verdict = "SUSPICIOUS"

    else:

        verdict = "DANGEROUS"

    # Special protection:
    # one isolated malicious detection cannot produce
    # DANGEROUS by itself.

    if malicious == 1 and suspicious <= 1:

        verdict = "SUSPICIOUS"
        risk = min(risk, 59)

    return {
        "verdict": verdict,
        "risk_score": risk,
        "flags": flags,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected
    }


# ============================================================
# GROQ ANALYSIS
# ============================================================

def call_groq(target, source_results, base_analysis):

    api_key = os.getenv("GROQ_API_KEY")

    if not api_key:
        raise RuntimeError(
            "GROQ_API_KEY is not configured."
        )

    model = choose_model(api_key)

    prompt = f"""
You are the AI security analyst for Cyberlense.

Analyze this target:

TARGET:
{target}

SOURCE EVIDENCE:
{json.dumps(source_results, indent=2, default=str)}

DETERMINISTIC BASELINE:
{json.dumps(base_analysis, indent=2)}

IMPORTANT SECURITY RULES:

1. Do NOT automatically classify a target as DANGEROUS
   because of one isolated VirusTotal malicious detection.

2. A single isolated detection can be a false positive.
   In that situation, prefer SUSPICIOUS and clearly explain
   that further verification is recommended.

3. Multiple independent malicious detections are stronger
   evidence.

4. WHOIS information is supporting evidence only.
   An old domain does not automatically make it safe.

5. Missing WHOIS information means uncertainty.
   It does NOT automatically mean malicious.

6. VirusTotal harmless results should be considered.

7. Do not invent facts that are not present in the evidence.

8. Your explanation must be based only on the supplied evidence.

Return ONLY valid JSON.

Required JSON format:

{{
  "verdict": "SAFE | SUSPICIOUS | DANGEROUS",
  "risk_score": 0,
  "summary": "short explanation",
  "reasons": [
    "reason 1",
    "reason 2",
    "reason 3"
  ],
  "recommendation": "what the user should do",
  "false_positive_possible": true
}}

The deterministic baseline is a safety constraint.
Do not make an isolated single malicious detection
automatically become DANGEROUS.
"""

    endpoint = (
        "https://api.groq.com/openai/v1/chat/completions"
    )

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    candidate_models = [
        model,
        "llama-3.1-8b-instant",
        "openai/gpt-oss-20b",
        "openai/gpt-oss-120b",
        "llama-3.3-70b-versatile"
    ]

    # Remove duplicates
    candidate_models = list(
        dict.fromkeys(candidate_models)
    )

    last_error = None

    for candidate in candidate_models:

        payload = {
            "model": candidate,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a cybersecurity analysis "
                        "assistant. Return valid JSON only."
                    )
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.1,
            "max_tokens": 700,
            "response_format": {
                "type": "json_object"
            }
        }

        try:

            response = requests.post(
                endpoint,
                headers=headers,
                json=payload,
                timeout=60
            )

            if response.status_code == 401:

                raise RuntimeError(
                    "Groq API key is invalid."
                )

            if response.status_code == 429:

                raise RuntimeError(
                    "Groq API rate limit reached."
                )

            if response.status_code in (400, 403, 404):

                last_error = (
                    f"{candidate}: "
                    f"HTTP {response.status_code}"
                )

                continue

            if response.status_code != 200:

                last_error = (
                    f"{candidate}: "
                    f"HTTP {response.status_code} - "
                    f"{response.text[:300]}"
                )

                continue

            result = response.json()

            content = (
                result
                .get("choices", [{}])[0]
                .get("message", {})
                .get("content", "")
            )

            if not content:

                last_error = (
                    f"{candidate}: Empty response"
                )

                continue

            try:

                parsed = json.loads(content)

            except json.JSONDecodeError:

                # Try extracting JSON object
                match = re.search(
                    r"\{.*\}",
                    content,
                    re.DOTALL
                )

                if not match:

                    last_error = (
                        f"{candidate}: Invalid JSON"
                    )

                    continue

                parsed = json.loads(
                    match.group(0)
                )

            parsed["_model_used"] = candidate

            return parsed

        except RuntimeError:
            raise

        except Exception as e:

            last_error = str(e)

    raise RuntimeError(
        "Groq analysis failed. "
        + str(last_error)
    )


# ============================================================
# FINAL VERDICT SAFETY NORMALIZATION
# ============================================================

def normalize_final_result(ai_result, base_analysis):

    verdict = str(
        ai_result.get(
            "verdict",
            base_analysis["verdict"]
        )
    ).upper().strip()

    if verdict not in [
        "SAFE",
        "SUSPICIOUS",
        "DANGEROUS"
    ]:

        verdict = base_analysis["verdict"]

    try:

        score = int(
            ai_result.get(
                "risk_score",
                base_analysis["risk_score"]
            )
        )

    except Exception:

        score = base_analysis["risk_score"]

    score = max(
        0,
        min(
            100,
            score
        )
    )

    malicious = base_analysis["malicious"]
    suspicious = base_analysis["suspicious"]

    # --------------------------------------------------------
    # HARD SAFETY RULES
    # --------------------------------------------------------

    # One isolated malicious detection cannot become
    # DANGEROUS automatically.

    if malicious == 1 and suspicious <= 1:

        verdict = "SUSPICIOUS"
        score = min(score, 59)

    # No malicious or suspicious detections should not be
    # classified DANGEROUS by AI alone.

    elif malicious == 0 and suspicious == 0:

        verdict = "SAFE"
        score = min(score, 25)

    # Multiple malicious detections require at least
    # SUSPICIOUS.

    elif malicious >= 2:

        if score >= 70:
            verdict = "DANGEROUS"
        else:
            verdict = "SUSPICIOUS"

    # If deterministic analysis is more severe, don't
    # silently downgrade it.

    if base_analysis["verdict"] == "DANGEROUS":

        verdict = "DANGEROUS"
        score = max(
            score,
            base_analysis["risk_score"]
        )

    return {
        "verdict": verdict,
        "risk_score": score,
        "summary": ai_result.get(
            "summary",
            "Analysis completed."
        ),
        "reasons": ai_result.get(
            "reasons",
            base_analysis["flags"]
        ),
        "recommendation": ai_result.get(
            "recommendation",
            "Review the available security evidence."
        ),
        "false_positive_possible": ai_result.get(
            "false_positive_possible",
            malicious == 1
        ),
        "_model_used": ai_result.get(
            "_model_used",
            "Unknown"
        )
    }


# ============================================================
# UI
# ============================================================

st.markdown("### 🔎 Scan an IP, Domain or URL")

target = st.text_input(
    "Enter target",
    placeholder="example.com or https://example.com or 8.8.8.8",
    label_visibility="collapsed"
)

scan = st.button(
    "🛡️ Scan with Cyberlense",
    use_container_width=True
)


# ============================================================
# SCAN
# ============================================================

if scan:

    valid, validation_message = validate_target(
        target
    )

    if not valid:

        st.error(validation_message)
        st.stop()

    st.info(
        f"✓ {validation_message}"
    )

    with st.spinner(
        "Collecting VirusTotal and WHOIS intelligence..."
    ):

        source_results = run_sources(
            target
        )

    # --------------------------------------------------------
    # Show sources
    # --------------------------------------------------------

    st.markdown("## 🔎 Security Intelligence")

    vt = source_results.get(
        "VirusTotal",
        {}
    )

    whois_result = source_results.get(
        "WHOIS",
        {}
    )

    col1, col2 = st.columns(2)

    # --------------------------------------------------------
    # VirusTotal
    # --------------------------------------------------------

    with col1:

        st.markdown("### 🦠 VirusTotal")

        if vt.get("success"):

            data = vt.get(
                "data",
                {}
            )

            a, b = st.columns(2)
            c, d = st.columns(2)

            with a:
                st.metric(
                    "Malicious",
                    data.get("malicious", 0)
                )

            with b:
                st.metric(
                    "Suspicious",
                    data.get("suspicious", 0)
                )

            with c:
                st.metric(
                    "Harmless",
                    data.get("harmless", 0)
                )

            with d:
                st.metric(
                    "Undetected",
                    data.get("undetected", 0)
                )

            if data.get("exact_url_checked"):

                st.success(
                    "Exact URL reputation checked."
                )

            else:

                st.info(
                    "Domain/IP reputation checked."
                )

        else:

            st.warning(
                "VirusTotal unavailable: "
                + str(vt.get("error"))
            )

    # --------------------------------------------------------
    # WHOIS
    # --------------------------------------------------------

    with col2:

        st.markdown("### 🌐 WHOIS")

        if whois_result.get("success"):

            data = whois_result.get(
                "data",
                {}
            )

            if data.get("available") is False:

                st.info(
                    data.get(
                        "message",
                        "WHOIS not applicable."
                    )
                )

            else:

                creation = data.get(
                    "creation_date"
                )

                age = data.get(
                    "domain_age_days"
                )

                st.write(
                    "**Domain:**",
                    data.get("domain", "N/A")
                )

                st.write(
                    "**Registrar:**",
                    data.get("registrar", "N/A")
                )

                st.write(
                    "**Created:**",
                    creation or "N/A"
                )

                if age is not None:

                    st.write(
                        f"**Domain Age:** "
                        f"{age:,} days"
                    )

        else:

            st.warning(
                "WHOIS unavailable: "
                + str(
                    whois_result.get("error")
                )
            )

    # --------------------------------------------------------
    # Deterministic baseline
    # --------------------------------------------------------

    base_analysis = calculate_base_risk(
        source_results
    )

    # --------------------------------------------------------
    # Groq
    # --------------------------------------------------------

    with st.spinner(
        "🤖 Groq AI is analyzing the evidence..."
    ):

        try:

            ai_result = call_groq(
                target,
                source_results,
                base_analysis
            )

            final_result = normalize_final_result(
                ai_result,
                base_analysis
            )

        except Exception as e:

            st.error(
                "Groq analysis failed: "
                + str(e)
            )

            # Still provide deterministic result
            final_result = {
                "verdict": base_analysis["verdict"],
                "risk_score": base_analysis["risk_score"],
                "summary": (
                    "AI analysis was unavailable. "
                    "The result below is based on "
                    "deterministic security evidence."
                ),
                "reasons": base_analysis["flags"],
                "recommendation": (
                    "Review the VirusTotal and WHOIS "
                    "evidence before trusting the target."
                ),
                "false_positive_possible": (
                    base_analysis["malicious"] == 1
                ),
                "_model_used": "Deterministic fallback"
            }

    # --------------------------------------------------------
    # FINAL RESULT
    # --------------------------------------------------------

    verdict = final_result["verdict"]
    score = final_result["risk_score"]

    st.markdown("---")
    st.markdown("## 🛡️ Cyberlense Verdict")

    if verdict == "SAFE":

        st.markdown(
            f"""
            <div class="safe">
                <h1>🟢 SAFE</h1>
                <h2>Risk Score: {score}/100</h2>
            </div>
            """,
            unsafe_allow_html=True
        )

    elif verdict == "SUSPICIOUS":

        st.markdown(
            f"""
            <div class="suspicious">
                <h1>🟡 SUSPICIOUS</h1>
                <h2>Risk Score: {score}/100</h2>
            </div>
            """,
            unsafe_allow_html=True
        )

    else:

        st.markdown(
            f"""
            <div class="dangerous">
                <h1>🔴 DANGEROUS</h1>
                <h2>Risk Score: {score}/100</h2>
            </div>
            """,
            unsafe_allow_html=True
        )

    # --------------------------------------------------------
    # AI EXPLANATION
    # --------------------------------------------------------

    st.markdown("### 🤖 AI Analysis")

    st.write(
        final_result.get(
            "summary",
            "No summary available."
        )
    )

    st.markdown("### Why?")

    reasons = final_result.get(
        "reasons",
        []
    )

    if isinstance(reasons, list):

        for reason in reasons:

            st.write(
                "• " + str(reason)
            )

    else:

        st.write(
            str(reasons)
        )

    st.markdown("### 💡 Recommendation")

    st.info(
        final_result.get(
            "recommendation",
            "Review the security evidence."
        )
    )

    if final_result.get(
        "false_positive_possible"
    ):

        st.warning(
            "⚠️ A false positive is possible. "
            "An isolated security-engine detection "
            "should not be treated as definitive proof "
            "of malicious activity."
        )

    st.caption(
        "AI model used: "
        + str(
            final_result.get(
                "_model_used",
                "Unknown"
            )
        )
    )

    # --------------------------------------------------------
    # RAW SOURCE DATA
    # --------------------------------------------------------

    with st.expander(
        "🔍 View technical source data"
    ):

        st.json(
            source_results
        )


# ============================================================
# FOOTER
# ============================================================

st.markdown("---")

st.caption(
    "Cyberlense uses VirusTotal, WHOIS and Groq AI. "
    "Results are informational and should not be treated "
    "as absolute proof of safety or maliciousness."
)
'''

with open("app.py", "w", encoding="utf-8") as f:
    f.write(app_code)

print("✓ app.py created")


# ================================================================
# 5. CREATE requirements.txt
# ================================================================

requirements = """streamlit
requests
python-whois
pyngrok
"""

with open(
    "requirements.txt",
    "w",
    encoding="utf-8"
) as f:
    f.write(requirements)

print("✓ requirements.txt created")


# ================================================================
# 6. START STREAMLIT + NGROK SAFELY
# ================================================================

import subprocess
import sys
import time
import requests

from pyngrok import ngrok


PORT = 8501
HOST = "127.0.0.1"


print("\n" + "=" * 70)
print("🛡️  STARTING CYBERLENSE")
print("=" * 70)


# ------------------------------------------------
# Stop old Streamlit
# ------------------------------------------------

print("\n🧹 Cleaning old Streamlit processes...")

subprocess.run(
    ["pkill", "-f", "streamlit"],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL
)

time.sleep(2)


# ------------------------------------------------
# Stop old ngrok
# ------------------------------------------------

print("🧹 Cleaning old ngrok tunnels...")

try:
    ngrok.kill()
except Exception:
    pass

time.sleep(1)


# ------------------------------------------------
# Configure ngrok
# ------------------------------------------------

print("🔐 Configuring ngrok...")

ngrok.set_auth_token(
    NGROK_AUTH_TOKEN
)

print("✓ ngrok authentication configured")


# ------------------------------------------------
# Start Streamlit
# ------------------------------------------------

print("\n🚀 Starting Streamlit...")

streamlit_process = subprocess.Popen(
    [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        "app.py",
        "--server.address",
        HOST,
        "--server.port",
        str(PORT),
        "--server.headless",
        "true",
        "--browser.gatherUsageStats",
        "false"
    ],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL
)


# ------------------------------------------------
# Wait until Streamlit is REALLY ready
# ------------------------------------------------

print("⏳ Waiting for Streamlit...")

streamlit_ready = False

for attempt in range(40):

    # Check if Streamlit process died
    if streamlit_process.poll() is not None:

        print(
            "\n❌ Streamlit stopped unexpectedly."
        )

        raise RuntimeError(
            "Streamlit failed to start. "
            "Check app.py for an error."
        )

    try:

        response = requests.get(
            f"http://{HOST}:{PORT}",
            timeout=1
        )

        if response.status_code == 200:

            streamlit_ready = True
            break

    except Exception:
        pass

    time.sleep(1)


if not streamlit_ready:

    raise RuntimeError(
        "❌ Streamlit did not become ready "
        "within the expected time."
    )


print(
    f"✓ Streamlit is READY at "
    f"http://{HOST}:{PORT}"
)


# ------------------------------------------------
# Start ngrok ONLY AFTER Streamlit is ready
# ------------------------------------------------

print("\n🌐 Starting ngrok...")

try:

    tunnel = ngrok.connect(
        addr=f"{HOST}:{PORT}",
        proto="http"
    )

except Exception as e:

    raise RuntimeError(
        f"❌ ngrok failed: {e}"
    )


public_url = tunnel.public_url


# ================================================================
# FINAL STATUS
# ================================================================

print("\n" + "=" * 70)
print("🛡️  CYBERLENSE STARTED SUCCESSFULLY")
print("=" * 70)

print("\n🌐 YOUR PUBLIC APP URL:")
print(public_url)

print("\n🔐 Secrets loaded securely:")
print("   ✓ VIRUSTOTAL_API_KEY")
print("   ✓ GROQ_API_KEY")
print("   ✓ NGROK_AUTH_TOKEN")

print("\n🤖 AI:")
print("   ✓ Groq API")
print("   ✓ Automatic model detection")
print("   ✓ Automatic model fallback")
print("   ✓ JSON output mode")

print("\n🔎 Security Sources:")
print("   ✓ VirusTotal")
print("   ✓ WHOIS")

print("\n🛡️ Risk Protection:")
print("   ✓ Single VT detection ≠ automatically dangerous")
print("   ✓ False-positive warning")
print("   ✓ Deterministic safety layer")
print("   ✓ AI explanation layer")

print("\n📁 Files created:")
print("   ✓ app.py")
print("   ✓ sources.py")
print("   ✓ requirements.txt")

print("\n" + "=" * 70)
print("Open the URL above to use Cyberlense.")
print("=" * 70)
