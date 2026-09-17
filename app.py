import os
import json
import re
import requests
import streamlit as st

from sources import (
    run_sources,
    is_ip,
    is_url,
    extract_domain
)

# --------------------------------------------------
# STREAMLIT CLOUD SECRETS
# --------------------------------------------------

VIRUSTOTAL_API_KEY = st.secrets.get("VIRUSTOTAL_API_KEY", "")
GROQ_API_KEY = st.secrets.get("GROQ_API_KEY", "")

if not VIRUSTOTAL_API_KEY:
    st.error("VIRUSTOTAL_API_KEY is missing from Streamlit Secrets.")
    st.stop()

if not GROQ_API_KEY:
    st.error("GROQ_API_KEY is missing from Streamlit Secrets.")
    st.stop()

os.environ["VIRUSTOTAL_API_KEY"] = VIRUSTOTAL_API_KEY
os.environ["GROQ_API_KEY"] = GROQ_API_KEY

# --------------------------------------------------
# PAGE CONFIG
# --------------------------------------------------

st.set_page_config(
    page_title="Cyberlense",
    page_icon="🛡️",
    layout="wide"
)

# --------------------------------------------------
# CUSTOM CSS
# --------------------------------------------------

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
    </style>
    """,
    unsafe_allow_html=True
)

# --------------------------------------------------
# HEADER
# --------------------------------------------------

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

# --------------------------------------------------
# VALIDATION
# --------------------------------------------------

def validate_target(target):
    target = target.strip()

    if not target:
        return False, "Please enter an IP address, domain, or URL."

    if is_ip(target):
        return True, "Valid IP address"

    if is_url(target):
        try:
            domain = extract_domain(target)

            if domain:
                return True, "Valid URL"

        except Exception:
            pass

        return False, "Invalid URL."

    domain_pattern = (
        r"^(?=.{1,253}$)"
        r"(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9-]{0,61}"
        r"[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,63}$"
    )

    if re.match(domain_pattern, target):
        return True, "Valid domain"

    return False, "Enter a valid IP address, domain, or URL."

# --------------------------------------------------
# GROQ MODEL
# --------------------------------------------------

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
        raise RuntimeError("Groq API key is invalid or expired.")

    if response.status_code == 429:
        raise RuntimeError("Groq API rate limit reached.")

    if response.status_code != 200:
        raise RuntimeError(
            f"Groq model discovery failed: HTTP {response.status_code}"
        )

    payload = response.json()

    return [
        item.get("id")
        for item in payload.get("data", [])
        if item.get("id")
    ]


def choose_model(api_key):
    preferred_models = [
        "llama-3.1-8b-instant",
        "openai/gpt-oss-20b",
        "openai/gpt-oss-120b",
        "llama-3.3-70b-versatile",
        "qwen/qwen3-32b"
    ]

    try:
        available_models = get_groq_models(api_key)

        for model in preferred_models:
            if model in available_models:
                return model

        for model in available_models:
            model_name = model.lower()

            if (
                "llama" in model_name
                or "gpt-oss" in model_name
                or "qwen" in model_name
            ):
                return model

        if available_models:
            return available_models[0]

    except Exception:
        pass

    return "llama-3.1-8b-instant"

# --------------------------------------------------
# DETERMINISTIC RISK ANALYSIS
# --------------------------------------------------

def calculate_base_risk(source_results):
    vt = source_results.get("VirusTotal", {})
    whois_result = source_results.get("WHOIS", {})

    vt_data = vt.get("data", {}) if vt.get("success") else {}

    whois_data = (
        whois_result.get("data", {})
        if whois_result.get("success")
        else {}
    )

    malicious = int(vt_data.get("malicious", 0) or 0)
    suspicious = int(vt_data.get("suspicious", 0) or 0)
    harmless = int(vt_data.get("harmless", 0) or 0)
    undetected = int(vt_data.get("undetected", 0) or 0)

    risk = 10
    flags = []

    if malicious == 0:
        risk = 10

    elif malicious == 1:
        risk = 45
        flags.append(
            "One isolated malicious detection requires further review."
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

    if suspicious >= 1:
        risk += min(suspicious * 5, 20)

        flags.append(
            f"{suspicious} suspicious detections were reported."
        )

    age_days = whois_data.get("domain_age_days")

    if age_days is not None:
        if age_days < 30:
            risk += 15
            flags.append("Domain appears very recently registered.")

        elif age_days < 180:
            risk += 8
            flags.append("Domain is relatively new.")

        elif age_days > 3650:
            risk -= 5

    elif whois_result.get("success") is False:
        flags.append("WHOIS information could not be verified.")

    if malicious == 0 and suspicious == 0:
        risk = min(risk, 20)

        if harmless > 0:
            flags.append(
                f"{harmless} VirusTotal engines marked it harmless."
            )

    risk = max(0, min(100, risk))

    if risk <= 25:
        verdict = "SAFE"

    elif risk <= 69:
        verdict = "SUSPICIOUS"

    else:
        verdict = "DANGEROUS"

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

# --------------------------------------------------
# GROQ ANALYSIS
# --------------------------------------------------

def call_groq(target, source_results, base_analysis):
    api_key = os.getenv("GROQ_API_KEY")

    if not api_key:
        raise RuntimeError("GROQ_API_KEY is not configured.")

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

Rules:
1. Do not classify a target as DANGEROUS because of one isolated
   VirusTotal malicious detection.
2. A single isolated detection may be a false positive.
3. Multiple independent malicious detections are stronger evidence.
4. WHOIS information is supporting evidence only.
5. Missing WHOIS information means uncertainty.
6. Do not invent facts.
7. Use only the supplied evidence.

Return only valid JSON in this format:

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
"""

    endpoint = "https://api.groq.com/openai/v1/chat/completions"

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": "You are a cybersecurity analyst. Return valid JSON only."
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

    response = requests.post(
        endpoint,
        headers=headers,
        json=payload,
        timeout=60
    )

    if response.status_code == 401:
        raise RuntimeError("Groq API key is invalid.")

    if response.status_code == 429:
        raise RuntimeError("Groq API rate limit reached.")

    if response.status_code != 200:
        raise RuntimeError(
            f"Groq API failed: HTTP {response.status_code}"
        )

    result = response.json()

    content = (
        result
        .get("choices", [{}])[0]
        .get("message", {})
        .get("content", "")
    )

    if not content:
        raise RuntimeError("Groq returned an empty response.")

    try:
        parsed_result = json.loads(content)

    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", content, re.DOTALL)

        if not match:
            raise RuntimeError("Groq returned invalid JSON.")

        parsed_result = json.loads(match.group(0))

    parsed_result["_model_used"] = model

    return parsed_result

# --------------------------------------------------
# FINAL RESULT NORMALIZATION
# --------------------------------------------------

def normalize_final_result(ai_result, base_analysis):
    verdict = str(
        ai_result.get(
            "verdict",
            base_analysis["verdict"]
        )
    ).upper().strip()

    if verdict not in ["SAFE", "SUSPICIOUS", "DANGEROUS"]:
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

    score = max(0, min(100, score))

    malicious = base_analysis["malicious"]
    suspicious = base_analysis["suspicious"]

    if malicious == 1 and suspicious <= 1:
        verdict = "SUSPICIOUS"
        score = min(score, 59)

    elif malicious == 0 and suspicious == 0:
        verdict = "SAFE"
        score = min(score, 25)

    elif malicious >= 2:
        verdict = "DANGEROUS" if score >= 70 else "SUSPICIOUS"

    if base_analysis["verdict"] == "DANGEROUS":
        verdict = "DANGEROUS"
        score = max(score, base_analysis["risk_score"])

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

# --------------------------------------------------
# USER INTERFACE
# --------------------------------------------------

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

# --------------------------------------------------
# SCAN
# --------------------------------------------------

if scan:
    valid, validation_message = validate_target(target)

    if not valid:
        st.error(validation_message)
        st.stop()

    st.info(f"✓ {validation_message}")

    with st.spinner("Collecting VirusTotal and WHOIS intelligence..."):
        source_results = run_sources(target)

    st.markdown("## 🔎 Security Intelligence")

    vt = source_results.get("VirusTotal", {})
    whois_result = source_results.get("WHOIS", {})

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### 🦠 VirusTotal")

        if vt.get("success"):
            data = vt.get("data", {})

            a, b = st.columns(2)
            c, d = st.columns(2)

            with a:
                st.metric("Malicious", data.get("malicious", 0))

            with b:
                st.metric("Suspicious", data.get("suspicious", 0))

            with c:
                st.metric("Harmless", data.get("harmless", 0))

            with d:
                st.metric("Undetected", data.get("undetected", 0))

        else:
            st.warning(
                "VirusTotal unavailable: "
                + str(vt.get("error"))
            )

    with col2:
        st.markdown("### 🌐 WHOIS")

        if whois_result.get("success"):
            data = whois_result.get("data", {})

            if data.get("available") is False:
                st.info(data.get("message", "WHOIS not applicable."))

            else:
                st.write("**Domain:**", data.get("domain", "N/A"))
                st.write("**Registrar:**", data.get("registrar", "N/A"))
                st.write("**Created:**", data.get("creation_date", "N/A"))

                if data.get("domain_age_days") is not None:
                    st.write(
                        "**Domain Age:**",
                        f"{data['domain_age_days']:,} days"
                    )

        else:
            st.warning(
                "WHOIS unavailable: "
                + str(whois_result.get("error"))
            )

    base_analysis = calculate_base_risk(source_results)

    with st.spinner("🤖 Groq AI is analyzing the evidence..."):
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

        except Exception as error:
            st.error(f"Groq analysis failed: {error}")

            final_result = {
                "verdict": base_analysis["verdict"],
                "risk_score": base_analysis["risk_score"],
                "summary": (
                    "AI analysis was unavailable. "
                    "The result below is based on deterministic evidence."
                ),
                "reasons": base_analysis["flags"],
                "recommendation": (
                    "Review the VirusTotal and WHOIS evidence "
                    "before trusting the target."
                ),
                "false_positive_possible": (
                    base_analysis["malicious"] == 1
                ),
                "_model_used": "Deterministic fallback"
            }

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

    st.markdown("### 🤖 AI Analysis")
    st.write(final_result.get("summary", "No summary available."))

    st.markdown("### Why?")

    reasons = final_result.get("reasons", [])

    if isinstance(reasons, list):
        for reason in reasons:
            st.write("• " + str(reason))
    else:
        st.write(str(reasons))

    st.markdown("### 💡 Recommendation")
    st.info(
        final_result.get(
            "recommendation",
            "Review the security evidence."
        )
    )

    if final_result.get("false_positive_possible"):
        st.warning(
            "A false positive is possible. "
            "An isolated security-engine detection should not "
            "be treated as definitive proof of malicious activity."
        )

    st.caption(
        "AI model used: "
        + str(final_result.get("_model_used", "Unknown"))
    )

    with st.expander("🔍 View technical source data"):
        st.json(source_results)

st.markdown("---")

st.caption(
    "Cyberlense uses VirusTotal, WHOIS and Groq AI. "
    "Results are informational and should not be treated "
    "as absolute proof of safety or maliciousness."
)
