from datetime import datetime, timezone

import pandas as pd
import streamlit as st
import hashlib
from datetime import datetime, timezone

from ai_analysis import analyze_text, analyze_image

from monitor import validate_onion_url, check_onion_site
from database import (
    connect_database,
    get_previous_fingerprint,
    save_observation,
    load_recent_observations,
)


st.set_page_config(
    page_title="DarkWatch Intelligence",
    page_icon="🛡️",
    layout="wide",
)


@st.cache_resource
def get_database():
    return connect_database()


try:
    mongo_client, observations = get_database()
except Exception as exc:
    st.error("MongoDB connection failed.")
    st.caption(
        f"Error type: {type(exc).__name__}. "
        "Check your .env file and Atlas configuration."
    )
    st.stop()

db = mongo_client["darkwatch"]

content_findings = db["content_findings"]

content_findings.create_index([
    ("source_ref", 1),
    ("analyzed_at", -1),
])

content_findings.create_index([
    ("content_hash", 1),
])


st.title("🛡️ DarkWatch Intelligence")
st.caption("Privacy-Preserving Onion Service Monitoring")

st.info(
    "Tracks reachability, response time, and public content changes. "
    "It does not measure third-party visitor counts."
)


with st.sidebar:
    st.header("Monitor Settings")

    target_input = st.text_input(
        "Public v3 onion URL",
        placeholder="http://your-public-address.onion/",
    )

    proxy_port = st.selectbox(
        "Local Tor SOCKS port",
        [9150, 9050],
        index=0,
    )

    confirmed = st.checkbox(
        "I will monitor only public pages and respect access restrictions."
    )

    check_button = st.button(
        "Check Website Now",
        type="primary",
        use_container_width=True,
    )


if not target_input.strip():
    st.info("Enter a permitted public v3 onion URL in the sidebar.")
    st.stop()

try:
    target_url = validate_onion_url(target_input)
except ValueError as exc:
    st.error(str(exc))
    st.stop()


if check_button:
    if not confirmed:
        st.warning("Confirm responsible monitoring before checking.")
    else:
        try:
            with st.spinner("Checking through Tor..."):
                result = check_onion_site(target_url, proxy_port)

            # Compare against the last complete fingerprint for this target.
            previous_hash = get_previous_fingerprint(
                observations,
                target_url,
            )

            fingerprint_complete = bool(
                result["content_hash"]
                and not result["body_truncated"]
            )

            content_changed = bool(
                fingerprint_complete
                and previous_hash is not None
                and previous_hash != result["content_hash"]
            )

            # Save a flexible MongoDB document.
            # No raw HTML or visitor information is stored.
            record = {
                "checked_at": datetime.now(timezone.utc),
                "target_url": target_url,
                "reachable": bool(result["reachable"]),
                "http_status": result["http_status"],
                "response_ms": result["response_ms"],
                "content_hash": (
                    result["content_hash"]
                    if fingerprint_complete
                    else None
                ),
                "fingerprint_complete": fingerprint_complete,
                "body_truncated": bool(result["body_truncated"]),
                "content_changed": content_changed,
                "error_type": result["error"],
                "metadata": {
                    "monitor_version": "0.1",
                    "trigger": "manual",
                },
            }

            save_observation(observations, record)

            if result["reachable"]:
                st.success(
                    f"Received HTTP {result['http_status']} "
                    f"in {result['response_ms']:.0f} ms."
                )
                if result["http_status"] >= 500:
                    st.warning("The server returned an HTTP error status.")
                if content_changed:
                    st.warning("A complete HTML fingerprint change was detected.")
            else:
                st.warning(
                    "No HTTP response received. Check the target and "
                    "your local Tor connection."
                )

        except Exception as exc:
            st.error("The check or database write failed.")
            st.caption(f"Error type: {type(exc).__name__}")


# Fetch persisted records from MongoDB, not Streamlit session memory.
try:
    history = load_recent_observations(
        observations,
        target_url,
        limit=100,
    )
except Exception as exc:
    st.error("Could not load the monitoring history from MongoDB.")
    st.caption(f"Error type: {type(exc).__name__}")
    st.stop()


if not history:
    st.info("No observations stored for this website yet.")
    st.stop()


df = pd.DataFrame(history)
df["checked_at"] = pd.to_datetime(
    df["checked_at"],
    utc=True,
    errors="coerce",
)

df = df.sort_values("checked_at")
latest = df.iloc[-1]

col1, col2, col3, col4 = st.columns(4)

col1.metric(
    "Latest Result",
    "HTTP Response" if latest["reachable"] else "No Response",
)

col2.metric(
    "HTTP Status",
    str(latest["http_status"])
    if pd.notna(latest["http_status"])
    else "—",
)

col3.metric(
    "Response Time",
    f"{latest['response_ms']:.0f} ms"
    if pd.notna(latest["response_ms"])
    else "—",
)

col4.metric(
    "Latest Content Change",
    "Yes" if latest["content_changed"] else "No",
)


st.subheader("Response Time History")

latency_df = df.dropna(
    subset=["checked_at", "response_ms"]
).set_index("checked_at")[["response_ms"]]

if not latency_df.empty:
    st.line_chart(latency_df)
else:
    st.caption("No response-time measurements available.")


st.subheader("Reachability History")

availability_df = df.copy()
availability_df["http_response_received"] = (
    availability_df["reachable"].astype(int)
)

availability_df = availability_df.set_index(
    "checked_at"
)[["http_response_received"]]

st.line_chart(availability_df)

st.caption(
    "1 means an HTTP response was received; 0 means no HTTP response "
    "was received. An HTTP error response still counts as a response."
)


st.subheader("Recent Observations")

display_df = df[
    [
        "checked_at",
        "reachable",
        "http_status",
        "response_ms",
        "content_changed",
        "fingerprint_complete",
        "body_truncated",
        "error_type",
    ]
].copy()

display_df["checked_at"] = display_df["checked_at"].dt.strftime(
    "%Y-%m-%d %H:%M:%S UTC"
)

st.dataframe(
    display_df.sort_values(
        "checked_at",
        ascending=False,
    ),
    use_container_width=True,
    hide_index=True,
)


st.download_button(
    "Export History as CSV",
    data=df.to_csv(index=False).encode("utf-8"),
    file_name="darkwatch_observations.csv",
    mime="text/csv",
)


st.caption(
    f"Stored observations in MongoDB: {len(df)} recent records shown."
)
st.header("AI Content Intelligence")

st.warning(
    "Use only eligible public content. AI findings are preliminary "
    "indicators and must not be treated as legal conclusions."
)

with st.expander("Analyze public text", expanded=True):

    source_ref = st.text_input(
        "Source URL or test label",
        value="hackathon-demo",
        key="ai_source_ref",
    )

    text_input = st.text_area(
        "Public text excerpt",
        placeholder=(
            "Paste a short, eligible public listing or comment "
            "for analysis. Start with synthetic test examples."
        ),
        max_chars=4000,
        height=150,
        key="ai_text_input",
    )

    safe_text_confirmed = st.checkbox(
        "I confirm this excerpt is eligible to process, contains "
        "no unnecessary personal data, and contains no known or "
        "suspected child sexual abuse material.",
        key="ai_text_confirmed",
    )

    if st.button("Analyze Text with AI", key="analyze_public_text"):

        if not safe_text_confirmed:
            st.warning("Review the data-safety confirmation first.")

        elif not text_input.strip():
            st.warning("Enter an eligible text excerpt.")

        else:
            try:
                with st.spinner("Analyzing the text..."):
                    ai_result = analyze_text(text_input)

                assessment = ai_result["assessment"]
                moderation = ai_result["moderation"]

                content_hash = hashlib.sha256(
                    text_input.encode("utf-8")
                ).hexdigest()

                record = {
                    "source_ref": (
                        source_ref.strip()[:300]
                        or "manual-test"
                    ),
                    "analyzed_at": datetime.now(timezone.utc),
                    "content_type": "text",
                    "content_hash": content_hash,
                    "assessment": assessment,
                    "moderation": moderation,
                    "classifier_model": ai_result["classifier_model"],
                    "moderation_model": ai_result["moderation_model"],
                    "review_status": "pending_review",
                }

                content_findings.insert_one(record)

                st.success("Analysis saved to MongoDB.")

                st.subheader("AI Assessment")

                st.write(
                    "**Preliminary category:**",
                    assessment["category"],
                )

                st.write(
                    "**Model confidence estimate:**",
                    f"{assessment['confidence']:.0%}",
                )

                st.write(
                    "**Evidence summary:**",
                    assessment["evidence_summary"],
                )

                st.write(
                    "**Context note:**",
                    assessment["context_note"],
                )

                st.write(
                    "**Human review required:**",
                    assessment["needs_human_review"],
                )

                st.subheader("Standard Moderation Results")

                moderation_item = moderation["results"][0]

                st.write(
                    "**Flagged by moderation:**",
                    moderation_item["flagged"],
                )

                st.json(moderation_item["categories"])
                st.json(moderation_item["category_scores"])

            except Exception as exc:
                st.error("The analysis could not be completed.")
                st.write("Error details:", str(exc))