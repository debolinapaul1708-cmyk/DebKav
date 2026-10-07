import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import hashlib
from pathlib import Path
import io

import pdfplumber


st.set_page_config(page_title="debkav | Cyber Defense", page_icon="◈", layout="wide")


MAP = {
    "scan": "Reconnaissance",
    "login_success": "Initial Access",
    "powershell": "Execution",
    "process_start": "Execution",
    "scheduled_task": "Persistence",
    "credential_dump": "Credential Access",
    "network_discovery": "Discovery",
    "remote_login": "Lateral Movement",
    "archive": "Collection",
    "upload": "Exfiltration",
    "ransomware": "Impact",
}

SEV = {
    "Reconnaissance": 0.25,
    "Initial Access": 0.45,
    "Execution": 0.55,
    "Persistence": 0.60,
    "Credential Access": 0.80,
    "Discovery": 0.50,
    "Lateral Movement": 0.90,
    "Collection": 0.85,
    "Exfiltration": 1.0,
    "Impact": 1.0,
}

ACTIONS = {
    "Reconnaissance": "Validate scan source and reduce exposed services.",
    "Initial Access": "Validate login context and enforce MFA.",
    "Execution": "Isolate the session and collect endpoint evidence.",
    "Persistence": "Review scheduled tasks, services and autoruns.",
    "Credential Access": "Reset affected credentials after validation.",
    "Discovery": "Limit enumeration privileges.",
    "Lateral Movement": "Segment the host and restrict remote administration.",
    "Collection": "Restrict sensitive paths and preserve evidence.",
    "Exfiltration": "Block suspicious egress and invoke incident response.",
    "Impact": "Activate incident response and isolate affected assets.",
}


st.markdown(
    """<style>
.stApp{background:linear-gradient(135deg,#07101d,#0b1627 60%,#08111f);color:#eef5ff}
.block-container{max-width:1500px}
.hero{padding:30px 34px;border-radius:22px;background:linear-gradient(110deg,#112b49,#101d31);border:1px solid #2e6591;margin-bottom:18px}
.hero h1{font-size:46px;margin:0}
.hero p{color:#a9c5df;font-size:18px}
.card{background:#101d31;border:1px solid #24415f;border-radius:16px;padding:20px;margin:10px 0}
.tag{display:inline-block;padding:6px 11px;border-radius:99px;background:#183653;color:#9fd6ff;font-size:12px;margin:8px 5px 0 0}
.small{color:#9cb0c7;font-size:13px}
</style>""",
    unsafe_allow_html=True,
)


def demo():
    start = datetime.now() - timedelta(minutes=40)
    rows = [
        [start, "host-20", "scanner", "scan", "10.0.0.5", "10.0.0.20", "nmap", 5],
        [
            start + timedelta(minutes=7),
            "host-20",
            "alice",
            "login_success",
            "10.0.0.5",
            "10.0.0.20",
            "sshd",
            5,
        ],
        [
            start + timedelta(minutes=14),
            "host-20",
            "alice",
            "powershell",
            "10.0.0.20",
            "10.0.0.20",
            "powershell",
            5,
        ],
        [
            start + timedelta(minutes=21),
            "host-20",
            "alice",
            "network_discovery",
            "10.0.0.20",
            "10.0.0.0/24",
            "net.exe",
            5,
        ],
        [
            start + timedelta(minutes=28),
            "host-20",
            "alice",
            "credential_dump",
            "10.0.0.20",
            "10.0.0.20",
            "lsass",
            5,
        ],
    ]
    return pd.DataFrame(
        rows,
        columns=[
            "timestamp",
            "host",
            "user",
            "event_type",
            "source",
            "destination",
            "process",
            "asset_criticality",
        ],
    )


def normalize(data):
    data = data.copy()
    for col in [
        "timestamp",
        "host",
        "user",
        "event_type",
        "source",
        "destination",
        "process",
    ]:
        if col not in data:
            data[col] = "unknown"
    if "asset_criticality" not in data:
        data["asset_criticality"] = 3
    data["timestamp"] = pd.to_datetime(data["timestamp"], errors="coerce").fillna(
        pd.Timestamp.now()
    )
    data["event_type"] = (
        data["event_type"].astype(str).str.lower().str.replace(" ", "_", regex=False)
    )
    data["behaviour"] = data["event_type"].map(MAP).fillna("Unmapped")
    return data.sort_values("timestamp").reset_index(drop=True)


def forecast(data):
    data = data[data.behaviour != "Unmapped"].copy()
    if data.empty:
        return None
    transitions = {}
    for _, group in data.groupby(["host", "user"]):
        sequence = group.behaviour.tolist()
        for current, nxt in zip(sequence, sequence[1:]):
            transitions.setdefault(current, []).append(nxt)

    current = data.iloc[-1].behaviour
    counts = pd.Series(transitions.get(current, []))
    counts = counts.value_counts() if not counts.empty else data.behaviour.value_counts()
    probabilities = counts / counts.sum()

    rows = []
    for stage, probability in probabilities.items():
        score = 100 * (
            0.45 * float(probability)
            + 0.25 * SEV.get(stage, 0.5)
            + 0.20 * float(data.iloc[-1].asset_criticality) / 5
            + 0.10
        )
        rows.append(
            {
                "Forecast": stage,
                "Probability": round(float(probability), 3),
                "Risk score": round(score, 1),
                "Recommended action": ACTIONS.get(
                    stage, "Validate with an analyst."
                ),
            }
        )
    return current, pd.DataFrame(rows)


def heuristic_scan(content: bytes, filename: str) -> dict:
    suspicious_exts = {".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".js", ".vbs"}
    suspicious_strings = [
        b"cmd.exe",
        b"powershell",
        b"mimikatz",
        b"lsass",
        b"reg add",
        b"schtasks",
        b"certutil",
        b"bitsadmin",
        b"wget",
        b"curl",
        b"invoke-webrequest",
        b"downloadfile",
        b"base64",
        b"whoami",
        b"net user",
        b"net localgroup",
    ]

    ext = Path(filename).suffix.lower()
    score = 0
    reasons = []

    if ext in suspicious_exts:
        score += 40
        reasons.append(f"Suspicious extension: {ext}")

    text = content.lower()
    for s in suspicious_strings:
        if s in text:
            score += 10
            reasons.append(f"Suspicious pattern: {s.decode(errors='ignore')}")

    score = min(score, 100)

    if score >= 70:
        status = "Likely malicious (heuristic)"
        recommendation = (
            "Do not execute. Isolate file, submit to EDR/AV, and investigate origin."
        )
    elif score >= 40:
        status = "Suspicious (heuristic)"
        recommendation = (
            "Do not execute on production. Validate with ClamAV/EDR and review source."
        )
    else:
        status = "No obvious indicators (heuristic)"
        recommendation = (
            "Treat as untrusted. Scan with ClamAV/EDR before use; monitor if executed in lab."
        )

    return {
        "Filename": filename,
        "Size": len(content),
        "SHA-256": hashlib.sha256(content).hexdigest(),
        "Heuristic score": score,
        "Status": status,
        "Recommended action": recommendation,
        "Indicators": "; ".join(reasons) if reasons else "None detected",
    }


def pdf_to_dataframe(file_obj) -> pd.DataFrame:
    """
    Extract the first table from the first page of the PDF and return as DataFrame.
    Assumes:
      - First row of the table is the header.
      - The table is reasonably well-structured.
    """
    with pdfplumber.open(file_obj) as pdf:
        if not pdf.pages:
            raise ValueError("PDF has no pages.")
        page = pdf.pages[0]
        tables = page.extract_tables()
        if not tables:
            raise ValueError("No tables found in PDF.")

        table = tables[0]
        # First row as header
        header = [str(h).strip() if h is not None else f"col_{i}" for i, h in enumerate(table[0])]
        rows = [
            [str(c).strip() if c is not None else "" for c in row]
            for row in table[1:]
        ]
        df = pd.DataFrame(rows, columns=header)
        return df


if "telemetry" not in st.session_state:
    st.session_state.telemetry = demo()


with st.sidebar:
    st.markdown("## ◈ debkav")
    st.caption("Information Security Defense Platform")
    page = st.radio(
        "Open module",
        ["SOC Dashboard", "Telemetry", "Attack Forecast", "Virus Scanner"],
    )
    if st.button("Load demo attack path", use_container_width=True):
        st.session_state.telemetry = demo()
    st.divider()
    st.caption(
        "NIST CSF: Govern • Identify • Protect • Detect • Respond • Recover"
    )


st.markdown(
    '<div class="hero"><h1>◈ debkav</h1><p>Defensive Behavioural Evidence and Kernel-Aware Virus Analysis</p>'
    '<span class="tag">MALWARE DETECTION</span><span class="tag">ATT&CK-ALIGNED</span>'
    '<span class="tag">RISK-BASED</span><span class="tag">EXPLAINABLE</span></div>',
    unsafe_allow_html=True,
)


data = normalize(st.session_state.telemetry)


if page == "SOC Dashboard":
    st.subheader("Live security command center")

    # Add stage number mapping
    behaviour_order = {b: i for i, b in enumerate(data["behaviour"].unique())}
    data_with_stage = data.copy()
    data_with_stage["stage_number"] = data_with_stage["behaviour"].map(behaviour_order)

    a, b, c, d = st.columns(4)
    a.metric("Telemetry events", len(data_with_stage))
    b.metric("Hosts observed", data_with_stage.host.nunique())
    c.metric("Mapped behaviours", int((data_with_stage.behaviour != "Unmapped").sum()))
    d.metric(
        "Current stage",
        f"{data_with_stage.behaviour.iloc[-1]} (#{data_with_stage.stage_number.iloc[-1]})",
    )

    left, right = st.columns([1.1, 1])
    with left:
        st.markdown(
            '<div class="card"><h3>NIST security lifecycle</h3></div>',
            unsafe_allow_html=True,
        )
        st.progress(1, text="Govern — authorization and audit")
        st.progress(1, text="Identify — assets and context")
        st.progress(1, text="Protect — MFA, least privilege and segmentation")
        st.progress(1, text="Detect — malware and telemetry analytics")
        st.progress(0.65, text="Respond — validation and containment")
        st.progress(0.45, text="Recover — restoration and monitoring")

    with right:
        st.markdown(
            f'<div class="card"><h3>Current attack path</h3>'
            f'<p>{" → ".join(data_with_stage.tail(8).behaviour)}</p></div>',
            unsafe_allow_html=True,
        )
        chart_df = (
            data_with_stage.set_index("timestamp")[["stage_number"]]
            .rename(columns={"stage_number": "StageNumber"})
        )
        st.line_chart(chart_df)

    st.subheader("Recent telemetry")
    display_cols = [
        "timestamp",
        "host",
        "user",
        "event_type",
        "behaviour",
        "stage_number",
        "source",
        "destination",
        "process",
        "asset_criticality",
    ]
    st.dataframe(
        data_with_stage.tail(10)[display_cols],
        use_container_width=True,
        hide_index=True,
    )


elif page == "Telemetry":
    st.subheader("Telemetry ingestion")

    uploaded = st.file_uploader(
        "Upload CSV, text, or PDF telemetry (PDF must contain a table)",
        type=["csv", "txt", "pdf"],
    )

    if uploaded:
        try:
            if uploaded.name.lower().endswith(".pdf"):
                df = pdf_to_dataframe(uploaded)
            else:
                content = uploaded.read().decode("utf-8", errors="replace")
                try:
                    uploaded.seek(0)
                    df = pd.read_csv(uploaded)
                except Exception:
                    uploaded.seek(0)
                    lines = content.splitlines()
                    delim = "," if "," in lines[0] else "\t"
                    df = pd.read_csv(io.StringIO(content), sep=delim, engine="python")

            st.session_state.telemetry = df
            data = normalize(st.session_state.telemetry)
            st.success("Telemetry loaded and normalized.")
        except Exception as e:
            st.error(f"Failed to load telemetry: {e}")

    st.dataframe(data, use_container_width=True, hide_index=True)
    st.download_button(
        "Export normalized telemetry",
        data.to_csv(index=False),
        "debkav_normalized.csv",
    )


elif page == "Attack Forecast":
    st.subheader("Sequential behavioural attack forecast")
    result = forecast(data)
    if result:
        current, candidates = result
        top = candidates.iloc[0]
        a, b, c = st.columns(3)
        a.metric("Current stage", current)
        b.metric("Predicted next stage", top.Forecast)
        c.metric("Risk score", f'{top["Risk score"]}/100')

        st.markdown(
            '<div class="card"><h3>Explainable alert</h3>'
            f'<p><b>Evidence:</b> {" → ".join(data.tail(8).behaviour)}</p>'
            f'<p><b>Probability:</b> {float(top.Probability):.0%}</p>'
            f'<p><b>Recommended action:</b> {top["Recommended action"]}</p></div>',
            unsafe_allow_html=True,
        )
        st.dataframe(candidates, use_container_width=True, hide_index=True)
        st.bar_chart(candidates.set_index("Forecast")["Probability"])
    else:
        st.warning("No mapped events available.")


elif page == "Virus Scanner":
    st.subheader("Virus detection interface")
    st.info(
        "This demo interface performs heuristic scanning only. For confirmed antivirus detection, "
        "install ClamAV (or another AV engine) and integrate it in the scan function."
    )
    uploaded = st.file_uploader(
        "Upload files for heuristic scan",
        accept_multiple_files=True,
        type=None,
    )
    if uploaded:
        rows = []
        for file in uploaded:
            content = file.getvalue()
            result = heuristic_scan(content, file.name)
            rows.append(result)

        scan = pd.DataFrame(rows)
        st.dataframe(scan, use_container_width=True, hide_index=True)
        st.download_button(
            "Download file report",
            scan.to_csv(index=False),
            "debkav_file_report.csv",
        )


st.caption(
    "debkav • visual information-security research prototype • defensive use only"
)