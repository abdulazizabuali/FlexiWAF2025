import streamlit as st
import pandas as pd
import json
import time
import os
import plotly.express as px
import requests
from datetime import datetime


# Determine stats.json path from environment or common mount points.
# You can set STATS_FILE environment variable in docker-compose to force a path.
STATS_FILE_ENV = os.getenv("STATS_FILE", "").strip()

possible_paths = [
    STATS_FILE_ENV,
    "/app/data/stats.json",   # expected path when ./data is mounted to /app/data
    "/app/output/stats.json", # alternate path used in docker-compose
    "./data/stats.json",      # relative path for local runs
    "/usr/src/app/data/stats.json",
    "/data/stats.json"
]

# choose the first existing path, or None if not found
STATS_FILE = next((p for p in possible_paths if p and os.path.exists(p)), None)

if not STATS_FILE:
    # log info to Streamlit UI so it's easy to diagnose path/mount problems
    st.sidebar.warning("stats.json not found. Checked paths: " + ", ".join([str(x) for x in possible_paths if x]))
else:
    st.sidebar.info(f"Using stats file: {STATS_FILE}")

API_URL = "http://flexiwaf_api:5000/api"

st.set_page_config(
    page_title="FlexiWAF Dashboard",
    layout="wide",
    page_icon="🛡️"
)

st.title("🛡️ FlexiWAF - Security Dashboard")


def load_data():
    """
    Load analysis stats from STATS_FILE.
    Returns parsed JSON dict or None on failure.
    """
    try:
        if STATS_FILE and os.path.exists(STATS_FILE):
            with open(STATS_FILE, 'r') as f:
                raw = f.read().strip()
                if not raw:
                    return None
                data = json.loads(raw)
                return data
        else:
            return None
    except json.JSONDecodeError as e:
        st.sidebar.error(f"Failed to parse stats.json: {e}")
        return None
    except Exception as e:
        st.sidebar.error(f"Error reading stats.json: {e}")
        return None


def format_hourly(hours_dict):
    # Ensure keys are strings of 0..23 and values ints
    ordered = [int(hours_dict.get(str(h), 0)) for h in range(24)]
    return ordered


def display_summary(data):
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        total_requests = data.get('total_requests', 0)
        st.metric("Total Requests", total_requests)
    with col2:
        total_rejections = data.get('total_rejections', 0)
        st.metric("Total Rejections", total_rejections)
    with col3:
        unique_ips = data.get('unique_ips', 0)
        st.metric("Unique IPs", unique_ips)
    with col4:
        last_updated = data.get('last_updated', 'N/A')
        try:
            st.metric("Last Updated", datetime.fromisoformat(last_updated).strftime("%Y-%m-%d %H:%M:%S") if last_updated != 'N/A' else 'N/A')
        except Exception:
            st.metric("Last Updated", last_updated)


def display_top_ips(data):
    st.subheader("Top 5 IPs by Rejection Count")
    top_5_ips = data.get('top_5_ips', {})
    if top_5_ips:
        df_top_ips = pd.DataFrame(list(top_5_ips.items()),
                                  columns=['IP Address', 'Rejection Count'])
        st.table(df_top_ips.sort_values('Rejection Count', ascending=False).head(5))
    else:
        st.info("No rejected IPs yet.")


def display_hourly_chart(data):
    st.subheader("Hourly Distribution")
    hourly = data.get('hourly_distribution', {})
    hours = list(range(24))
    values = format_hourly(hourly)
    df = pd.DataFrame({'hour': hours, 'requests': values})
    fig = px.bar(df, x='hour', y='requests', labels={'hour': 'Hour of day', 'requests': 'Requests'})
    st.plotly_chart(fig, use_container_width=True)


def display_rejection_types(data):
    st.subheader("Rejection Types")
    rtypes = data.get('rejection_types', {})
    if rtypes:
        df = pd.DataFrame(list(rtypes.items()), columns=['Status', 'Count'])
        st.table(df)
    else:
        st.info("No rejections recorded.")


def display_last_events(data):
    st.subheader("Last Events")
    events = data.get('last_10_events', [])
    if events:
        df = pd.DataFrame(events)
        # ensure timestamp column present and sorted
        if 'timestamp' in df.columns:
            try:
                df['parsed_ts'] = pd.to_datetime(df['timestamp'], errors='coerce')
                df = df.sort_values('parsed_ts', ascending=False).drop(columns=['parsed_ts'])
            except Exception:
                pass
        st.table(df.head(10))
    else:
        st.info("No events yet.")


def refresh_button():
    if st.button("Refresh data"):
        st.experimental_rerun()


def main():
    st.sidebar.markdown("## Controls")
    refresh_button()
    st.sidebar.markdown("### Debug")
    st.sidebar.markdown(f"Checked paths: {', '.join([str(x) for x in possible_paths if x])}")
    st.sidebar.markdown(f"Using: {STATS_FILE if STATS_FILE else 'None'}")

    # main loading loop
    data = load_data()
    if not data:
        st.info("⏳ Waiting for initial analysis data...")
        st.stop()

    # Display dashboard
    display_summary(data)
    st.write("---")
    display_top_ips(data)
    display_hourly_chart(data)
    display_rejection_types(data)
    st.write("---")
    display_last_events(data)

    # About / Footer
    with st.expander("About FlexiWAF"):
        st.header("About FlexiWAF")
        st.markdown("""
                    FlexiWAF is a lightweight and practical web application firewall built around NGINX/OpenResty. 
                    It is designed to provide dynamic and quickly adjustable security rules with low-latency performance.
                    **Key Features:**
                    - **Dynamic Filtering:** Blocks unwanted IPs based on a dynamic list.
                    - **Real-time Monitoring:** The dashboard provides live insights into traffic and rejection events.
                    - **Honeypot Traps:** Detects scanners and malicious bots.
                    - **CAPTCHA Challenge:** A rate-limiting feature that may redirect a suspicious client to solve a simple challenge upon exceeding the request limit.
                    This project is a perfect example of a comprehensive and integrated solution for web application security.
                    """)
        time.sleep(1)


if __name__ == "__main__":
    main()
