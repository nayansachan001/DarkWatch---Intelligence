from datetime import datetime, timezone

import pandas as pd
import streamlit as st

from monitor import validate_onion_url, check_onion_site


st.set_page_config(
    page_title="DarkWatch Intelligence",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ DarkWatch Intelligence")
st.caption("Onion Service Monitoring & Activity Intelligence")

st.info(
    "This prototype measures reachability, response time, "
    "and public content changes. It does not count visitors."
)

with st.sidebar:
    st.header("Monitor Settings")

    target_input = st.text_input(
        "Public v3 onion URL",
        placeholder="http://your-onion-address.onion/",
    )

    proxy_port = st.selectbox(
        "Local Tor SOCKS port",
        options=[9150, 9050],
        index=0,
    )

    confirmed = st.checkbox(
        "I will monitor only publicly accessible pages "
        "and respect access restrictions."
    )

    check_button = st.button(
        "Check Website Now",
        type="primary",
        use_container_width=True,
    )


if "history" not in st.session_state:
    st.session_state.history = []

if check_button:
    if not confirmed:
        st.warning("Please confirm responsible monitoring.")

    else:
        try:
            url = validate_onion_url(target_input)

            with st.spinner("Checking through Tor..."):
                result = check_onion_site(url, proxy_port)

            previous_hash = next(
                (
                    row["content_hash"]
                    for row in st.session_state.history
                    if row["url"] == url
                    and row["content_hash"]
                ),
                None,
            )

            content_changed = (
                bool(result["content_hash"])
                and previous_hash is not None
                and result["content_hash"] != previous_hash
            )

            record = {
                "time_utc": datetime.now(timezone.utc).strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "url": url,
                **result,
                "content_changed": content_changed,
            }

            st.session_state.history.insert(0, record)

            if result["reachable"]:
                st.success(
                    f"Received HTTP {result['http_status']} "
                    f"in {result['response_ms']:.0f} ms."
                )

                if result["http_status"] >= 500:
                    st.warning(
                        "The server responded with an error status."
                    )

                if content_changed:
                    st.warning(
                        "The observed HTML fingerprint has changed."
                    )
                elif result["content_hash"]:
                    st.info(
                        "HTML fingerprint recorded. A single check "
                        "cannot establish a content change."
                    )
            else:
                st.error(
                    "No HTTP response was received. Check the Tor "
                    "connection, selected port, and onion address."
                )

        except ValueError as exc:
            st.error(str(exc))


history = st.session_state.history

if history:
    df = pd.DataFrame(history)

    latest = history[0]

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Latest Result",
        "HTTP Response" if latest["reachable"] else "No Response",
    )

    col2.metric(
        "HTTP Status",
        str(latest["http_status"])
        if latest["http_status"] is not None
        else "—",
    )

    col3.metric(
        "Response Time",
        f"{latest['response_ms']:.0f} ms",
    )

    st.subheader("Response Time History")

    chart_data = df[["time_utc", "response_ms"]].copy()
    chart_data["time_utc"] = pd.to_datetime(
        chart_data["time_utc"], utc=True
    )
    chart_data = chart_data.sort_values("time_utc")

    st.line_chart(
        chart_data.set_index("time_utc")[["response_ms"]]
    )

    st.subheader("Content Change Events")

    changes = df[df["content_changed"]]

    if changes.empty:
        st.caption("No fingerprint changes observed so far.")
    else:
        st.dataframe(
            changes[["time_utc", "http_status", "content_changed"]],
            use_container_width=True,
            hide_index=True,
        )

    st.subheader("Recent Checks")

    display_columns = [
        "time_utc",
        "reachable",
        "http_status",
        "response_ms",
        "content_changed",
        "body_truncated",
        "error",
    ]

    st.dataframe(
        df[display_columns],
        use_container_width=True,
        hide_index=True,
    )

    st.download_button(
        "Export Checks as CSV",
        data=df.to_csv(index=False).encode("utf-8"),
        file_name="darkwatch_checks.csv",
        mime="text/csv",
    )

    st.caption(
        "History is currently held in the Streamlit session. "
        "It is not yet permanently stored in a database."
    )

else:
    st.info(
        "No real checks recorded yet. Configure Tor, enter a "
        "permitted public onion URL, and click Check Website Now."
    )