import streamlit as st
import pandas as pd
import json
import time
import os
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta, timezone

# ⚠️ الحل: نقل st.set_page_config() ليكون أول أمر Streamlit
st.set_page_config(
    page_title="FlexiWAF Dashboard",
    layout="wide",
    page_icon="🛡️"
)

# Custom CSS for modern dark theme
st.markdown(f"""
<style>
    :root {{
        --background: #1a1a1a;
        --card-bg: #2d2d2d;
        --border: #444;
        --text: #e0e0e0;
        --primary: #4a6fa5;
        --secondary: #6b8cbf;
        --danger: #dc3545;
        --warning: #ffc107;
        --info: #17a2b8;
        --success: #28a745;
    }}
    
    body {{
        background-color: var(--background);
        color: var(--text);
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    }}
    
    .stApp {{
        background-color: var(--background);
    }}
    
    .metric-card {{
        background: linear-gradient(135deg, var(--card-bg), #3a3a3a);
        padding: 20px;
        border-radius: 15px;
        text-align: center;
        box-shadow: 0 8px 25px rgba(0,0,0,0.5);
        margin: 10px;
        transition: transform 0.3s ease;
    }}
    
    .metric-card:hover {{
        transform: translateY(-5px);
        box-shadow: 0 12px 30px rgba(0,0,0,0.7);
    }}
    
    .metric-title {{
        font-size: 1.2rem;
        color: #aaa;
        margin-bottom: 8px;
        font-weight: 500;
    }}
    
    .metric-value {{
        font-size: 2.5rem;
        font-weight: 700;
        margin: 10px 0;
    }}
    
    .metric-delta {{
        font-size: 1rem;
        font-weight: 500;
    }}
    
    .attack-card {{
        background: var(--card-bg);
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 20px;
        margin: 15px 0;
    }}
    
    .threat-critical {{
        background-color: rgba(220, 53, 69, 0.15);
        border-left: 4px solid var(--danger);
    }}
    
    .threat-high {{
        background-color: rgba(255, 193, 7, 0.15);
        border-left: 4px solid var(--warning);
    }}
    
    .threat-medium {{
        background-color: rgba(23, 162, 184, 0.15);
        border-left: 4px solid var(--info);
    }}
    
    .last-updated {{
        text-align: right;
        color: #888;
        font-size: 0.9rem;
        margin-top: 20px;
    }}
    
    .footer {{
        text-align: center;
        padding: 20px;
        color: #888;
        border-top: 1px solid var(--border);
        margin-top: 30px;
    }}
    
    .attack-icon {{
        font-size: 1.5rem;
        margin-right: 10px;
    }}
</style>
""", unsafe_allow_html=True)

# Determine stats.json path from environment or common mount points.
STATS_FILE_ENV = os.getenv("STATS_FILE", "").strip()

possible_paths = [
    STATS_FILE_ENV,
    "/app/data/stats.json",    # expected path when ./data is mounted to /app/data
    "/app/output/stats.json", # alternate path used in docker-compose
    "./data/stats.json",      # relative path for local runs
    "./stats.json",           # ✅ مسار إضافي
    "/data/stats.json",
    "/usr/src/app/data/stats.json",
    "/mnt/data/stats.json"    # ✅ مسار إضافي للـ mount
]

# choose the first existing path, or None if not found
STATS_FILE = next((p for p in possible_paths if p and os.path.exists(p)), None)

# Modern color scheme
COLOR_SCHEME = {
    'background': '#1a1a1a',
    'card_bg': '#2d2d2d',
    'border': '#444',
    'text': '#e0e0e0',
    'primary': '#4a6fa5',
    'secondary': '#6b8cbf',
    'danger': '#dc3545',
    'warning': '#ffc107',
    'info': '#17a2b8',
    'success': '#28a745'
}

st.title("🛡️ FlexiWAF - Advanced Security Dashboard")

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

def format_time_ago(timestamp):
    """
    Format timestamp as 'X minutes ago' or 'X hours ago'
    """
    try:
        if isinstance(timestamp, str):
            # Handle different timestamp formats
            if timestamp.endswith('Z'):
                dt = datetime.fromisoformat(timestamp[:-1]).replace(tzinfo=timezone.utc)
            else:
                dt = datetime.fromisoformat(timestamp)
        elif isinstance(timestamp, datetime):
            dt = timestamp
        else:
            return timestamp
        
        now = datetime.utcnow().replace(tzinfo=timezone.utc)
        diff = now - dt
        
        if diff.total_seconds() < 60:
            return "Just now"
        elif diff.total_seconds() < 3600:
            minutes = int(diff.total_seconds() // 60)
            return f"{minutes} {'minute' if minutes == 1 else 'minutes'} ago"
        elif diff.total_seconds() < 86400:
            hours = int(diff.total_seconds() // 3600)
            return f"{hours} {'hour' if hours == 1 else 'hours'} ago"
        else:
            return dt.strftime("%Y-%m-%d %H:%M")
    except Exception as e:
        return str(timestamp)

def display_summary(data):
    """
    Display enhanced summary metrics with clear distinction between ban types
    """
    st.subheader("📊 Security Overview")
    
    # Row 1: Main Traffic & Attack Overview
    col1, col2, col3 = st.columns(3)
    
    with col1:
        total_requests = data.get('total_requests', 0)
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">✅ Total Requests</div>
            <div class="metric-value">{total_requests:,}</div>
            <div class="metric-delta">All traffic</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        # ✅ تمييز الحظر المؤقت vs الدائم
        temp_bans = data.get('temporary_bans', 0)
        perm_bans = data.get('permanent_bans', 0)
        total_attacks = temp_bans + perm_bans + data.get('honeypot_hits', 0)
        
        st.markdown(f"""
        <div class="metric-card" style="background: linear-gradient(135deg, #dc354520, #dc354510);">
            <div class="metric-title">⚔️ Total Blocks</div>
            <div class="metric-value" style="color: #dc3545;">{total_attacks:,}</div>
            <div class="metric-delta">
                <span style="color: #ffc107;">{temp_bans} Temp</span> • 
                <span style="color: #dc3545;">{perm_bans} Perm</span>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        unique_attackers = data.get('unique_attackers', 0)
        st.markdown(f"""
        <div class="metric-card" style="background: linear-gradient(135deg, #28a74520, #28a74510);">
            <div class="metric-title">👥 Unique Sources</div>
            <div class="metric-value" style="color: #28a745;">{unique_attackers:,}</div>
            <div class="metric-delta">Distinct IP addresses</div>
        </div>
        """, unsafe_allow_html=True)
        
    # Row 2: Attack Breakdown (Now 2 columns instead of 3)
    # The CAPTCHA Stats card is removed from this section as requested
    col4, col5 = st.columns(2)
    
    with col4:
        # ✅ الحظر المؤقت بسبب الكابتشا
        captcha_bans = data.get('temporary_bans', 0)
        st.markdown(f"""
        <div class="metric-card" style="background: linear-gradient(135deg, #ffc10720, #ffc10710);">
            <div class="metric-title">🔒 CAPTCHA Timeout Bans</div>
            <div class="metric-value" style="color: #ffc107;">{captcha_bans:,}</div>
            <div class="metric-delta">5 failed attempts → 5min ban</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col5:
        # ✅ الحظر الدائم من البلاك ليست
        blocklist_bans = data.get('permanent_bans', 0)
        st.markdown(f"""
        <div class="metric-card" style="background: linear-gradient(135deg, #dc354520, #dc354510);">
            <div class="metric-title">🚫 Permanent Bans</div>
            <div class="metric-value" style="color: #dc3545;">{blocklist_bans:,}</div>
            <div class="metric-delta">Blocklist IP addresses</div>
        </div>
        """, unsafe_allow_html=True)
    
    # The original content of col6 (CAPTCHA Stats) is now REMOVED
    # with col6:
    #     # ✅ إحصائيات دقيقة للكابتشا
    #     captcha_failures = data.get('captcha_failures', 0)
    #     captcha_success = data.get('captcha_success', 0)
    #     st.markdown(f"""
    #     <div class="metric-card" style="background: linear-gradient(135deg, #6b8cbf20, #6b8cbf10);">
    #         <div class="metric-title">⚠️ CAPTCHA Stats</div>
    #         <div class="metric-value" style="color: #6b8cbf;">{captcha_failures:,}</div>
    #         <div class="metric-delta">
    #             <span style="color: #28a745;">{captcha_success}✓</span> • 
    #             <span style="color: #dc3545;">{captcha_failures}✗</span>
    #         </div>
    #     </div>
    #     """, unsafe_allow_html=True)

def display_attack_types(data):
    """
    Display attack types distribution with clear ban type differentiation
    """
    st.subheader("⚔️ Security Events Distribution")
    
    rejection_breakdown = data.get('rejection_breakdown', {})
    if rejection_breakdown:
        # ✅ إعادة تنظيم البيانات لتعكس الأنواع الجديدة
        processed_data = {}
        for event_type, count in rejection_breakdown.items():
            if event_type == 'temporary_ban':
                processed_data['CAPTCHA Timeout Ban'] = count
            elif event_type == 'permanent_ban':
                processed_data['Permanent Block'] = count
            elif event_type == 'honeypot':
                processed_data['Honeypot Trigger'] = count
            elif event_type == 'captcha_fail':
                processed_data['CAPTCHA Failure'] = count
            elif event_type == 'rate_limit':
                processed_data['Rate Limit Exceeded'] = count
            else:
                processed_data[event_type] = count
        
        types = list(processed_data.keys())
        counts = list(processed_data.values())
        
        # ✅ نظام ألوان محسن للتمييز
        color_map = {
            'Permanent Block': '#dc3545',       # أحمر - خطير
            'CAPTCHA Timeout Ban': '#ffc107',    # أصفر - تحذير
            'CAPTCHA Failure': '#6b8cbf',        # أزرق - معلومات
            'Honeypot Trigger': '#17a2b8',       # أزرق فاتح - مراقبة
            'Rate Limit Exceeded': '#28a745'     # أخضر - طبيعي
        }
        
        colors = [color_map.get(t, COLOR_SCHEME['secondary']) for t in types]
        
        # ✅ إنشاء مخطط دائري مع تفاصيل محسنة
        fig = go.Figure(data=[go.Pie(
            labels=types,
            values=counts,
            hole=0.4,
            marker=dict(colors=colors, line=dict(color='#333', width=2)),
            textinfo='percent+label',
            textfont=dict(size=12, color='white'),
            hovertemplate="<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>",
            pull=[0.1 if 'Permanent' in t else 0 for t in types]  # إبراز الحظر الدائم
        )])
        
        fig.update_layout(
            title={
                'text': 'Distribution of Security Events',
                'font': {'size': 20, 'color': COLOR_SCHEME['text']},
                'x': 0.5,
                'xanchor': 'center'
            },
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font=dict(color=COLOR_SCHEME['text']),
            legend=dict(
                orientation="h",
                yanchor="bottom",
                y=1.02,
                xanchor="center",
                x=0.5,
                font=dict(color=COLOR_SCHEME['text'])
            ),
            height=400
        )
        
        st.plotly_chart(fig, use_container_width=True)
        
        # ✅ إضافة مفتاح الألوان التوضيحي
        st.markdown("""
        <div style="background: #2d2d2d; padding: 15px; border-radius: 10px; margin-top: 10px;">
            <h4 style="color: #e0e0e0; margin-bottom: 10px;">🎨 Event Type Legend:</h4>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
                <div><span style="color: #dc3545;">●</span> Permanent Block - IP in blocklist</div>
                <div><span style="color: #ffc107;">●</span> CAPTCHA Timeout - 5 failed attempts</div>
                <div><span style="color: #6b8cbf;">●</span> CAPTCHA Failure - Single failed attempt</div>
                <div><span style="color: #17a2b8;">●</span> Honeypot - Scanner detected</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.info("No security events data available yet. Wait for WAF to detect activity.")

def display_top_attackers(data):
    """
    Display top attackers with threat levels and enhanced formatting
    """
    st.subheader("🔥 Top Attackers")
    
    top_attackers = data.get('top_attackers', {})
    if top_attackers:
        # Create DataFrame
        df = pd.DataFrame({
            'IP Address': list(top_attackers.keys()),
            'Attack Count': list(top_attackers.values())
        })
        
        # Add threat level column
        def get_threat_level(count):
            if count > 50:
                return 'Critical 🔴'
            elif count > 20:
                return 'High 🟠'
            elif count > 10:
                return 'Medium 🟡'
            else:
                return 'Low 🟢'
        
        df['Threat Level'] = df['Attack Count'].apply(get_threat_level)
        
        # Add action buttons
        df['Actions'] = df['IP Address'].apply(lambda x: f"🚨 Block | ℹ️ Details")
        
        # Display as styled table
        st.dataframe(
            df.sort_values('Attack Count', ascending=False).head(10),
            column_config={
                "Attack Count": st.column_config.NumberColumn(
                    "⚔️ Attacks",
                    help="Number of detected attacks from this IP",
                    format="%d",
                ),
                "Threat Level": st.column_config.TextColumn(
                    "⚠️ Threat",
                    help="Threat assessment level"
                ),
                "Actions": st.column_config.TextColumn(
                    "🔧 Actions",
                    help="Available actions for this attacker"
                )
            },
            hide_index=True,
            use_container_width=True
        )
    else:
        st.info("No attackers detected yet. The system is monitoring for threats...")

def display_hourly_attacks(data):
    """
    Display hourly attack distribution with enhanced bar chart
    """
    st.subheader("⏰ Hourly Attack Distribution")
    
    hourly_attacks = data.get('hourly_attacks', {})
    if hourly_attacks:
        hours = list(range(24))
        counts = [hourly_attacks.get(str(h), 0) for h in hours]
        
        # Create DataFrame for Plotly
        df = pd.DataFrame({
            'Hour': [f"{h:02d}:00" for h in hours],
            'Attacks': counts
        })
        
        # Color bars based on attack count
        colors = ['#dc3545' if c > 50 else '#ffc107' if c > 20 else '#17a2b8' if c > 10 else '#28a745' for c in counts]
        
        fig = px.bar(
            df, 
            x='Hour', 
            y='Attacks',
            text='Attacks',
            labels={'Attacks': 'Number of Attacks', 'Hour': 'Hour of Day'},
            color_discrete_sequence=[COLOR_SCHEME['primary']]
        )
        
        fig.update_traces(
            marker_color=colors,
            textposition='outside',
            textfont=dict(color=COLOR_SCHEME['text'])
        )
        
        fig.update_layout(
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font=dict(color=COLOR_SCHEME['text']),
            xaxis=dict(
                tickmode='linear',
                title_font=dict(size=14, color=COLOR_SCHEME['text']),
                tickfont=dict(color=COLOR_SCHEME['text'])
            ),
            yaxis=dict(
                title_font=dict(size=14, color=COLOR_SCHEME['text']),
                tickfont=dict(color=COLOR_SCHEME['text']),
                gridcolor='#333'
            ),
            height=400
        )
        
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No hourly attack data available yet.")

def display_captcha_analytics(data):
    """
    Display detailed CAPTCHA analytics with accurate counters
    """
    st.subheader("🔐 CAPTCHA Performance Analytics")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        total_challenges = data.get('captcha_failures', 0) + data.get('captcha_success', 0)
        st.metric("Total Challenges", f"{total_challenges:,}", 
                  help="Total CAPTCHA challenges presented")
    
    with col2:
        success_rate = data.get('captcha_success_rate', 0)
        st.metric("Success Rate", f"{success_rate:.1f}%",
                  help="Percentage of successful CAPTCHA completions")
    
    with col3:
        avg_attempts = data.get('avg_captcha_attempts', 0)
        st.metric("Avg Attempts", f"{avg_attempts:.1f}",
                  help="Average attempts per challenge")
    
    with col4:
        timeout_rate = data.get('captcha_timeout_rate', 0)
        st.metric("Timeout Rate", f"{timeout_rate:.1f}%",
                  help="Percentage leading to temporary bans")
    
    # ✅ مخطط تقدم الكابتشا
    attempts_data = data.get('captcha_attempts_distribution', {})
    if attempts_data:
        fig = go.Figure()
        
        attempts = list(attempts_data.keys())
        counts = list(attempts_data.values())
        
        fig.add_trace(go.Bar(
            x=attempts,
            y=counts,
            name="Attempts Distribution",
            marker_color=['#28a745', '#ffc107', '#fd7e14', '#dc3545', '#721c24'],
            text=counts,
            textposition='auto',
        ))
        
        fig.update_layout(
            title="CAPTCHA Attempts Distribution",
            xaxis_title="Number of Attempts",
            yaxis_title="Count",
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font=dict(color=COLOR_SCHEME['text']),
            height=300
        )
        
        st.plotly_chart(fig, use_container_width=True)

def display_security_incidents(data):
    """
    Display security incidents with enhanced ban type differentiation
    """
    st.subheader("🚨 Recent Security Incidents")
    
    last_attacks = data.get('last_10_attacks', [])
    if last_attacks:
        incidents = []
        
        for attack in last_attacks:
            attack_type = attack.get('type', 'unknown')
            ip = attack.get('ip', 'unknown')
            details = attack.get('details', '')
            
            # ✅ نظام تصنيف محسن مع رموز وألوان
            if attack_type == 'temporary_ban':
                formatted_type = "⏰ CAPTCHA Timeout Ban"
                threat_level = "HIGH"
                duration = "5 minutes"
                reason = "5 failed CAPTCHA attempts"
                color = "#ffc107"
            elif attack_type == 'permanent_ban':
                formatted_type = "🚫 Permanent Block"
                threat_level = "CRITICAL"
                duration = "Permanent"
                reason = "IP in blocklist"
                color = "#dc3545"
            elif attack_type == 'honeypot':
                formatted_type = "🎯 Honeypot Trigger"
                threat_level = "MEDIUM"
                duration = "None"
                reason = "Scanner detected"
                color = "#17a2b8"
            elif attack_type == 'captcha_fail':
                formatted_type = "⚠️ CAPTCHA Failure"
                threat_level = "LOW"
                duration = "None"
                reason = "Single failed attempt"
                color = "#6b8cbf"
            elif attack_type == 'captcha_success':
                formatted_type = "✅ CAPTCHA Success"
                threat_level = "INFO"
                duration = "15 minutes grace"
                reason = "CAPTCHA passed"
                color = "#28a745"
            else:
                formatted_type = attack_type.replace('_', ' ').title()
                threat_level = "INFO"
                duration = "N/A"
                reason = details
                color = "#888"
            
            incident = {
                '⏰ Time': format_time_ago(attack.get('timestamp', 'N/A')),
                '🛡️ Type': formatted_type,
                '🌐 IP': ip,
                '⚠️ Threat': threat_level,
                '⏱️ Duration': duration,
                '📋 Reason': reason,
                'color': color
            }
            incidents.append(incident)
        
        # ✅ إنشاء DataFrame مع التنسيق
        df = pd.DataFrame(incidents)
        
        # ✅ دالة تنسيق مخصصة
        def style_row(row):
            styles = [''] * len(row)
            if 'CAPTCHA Timeout Ban' in row['🛡️ Type']:
                styles[1] = f'color: #ffc107; font-weight: bold;'
            elif 'Permanent Block' in row['🛡️ Type']:
                styles[1] = f'color: #dc3545; font-weight: bold;'
            elif 'Honeypot Trigger' in row['🛡️ Type']:
                styles[1] = f'color: #17a2b8; font-weight: bold;'
            elif 'CAPTCHA Failure' in row['🛡️ Type']:
                styles[1] = f'color: #6b8cbf;'
            elif 'CAPTCHA Success' in row['🛡️ Type']:
                styles[1] = f'color: #28a745; font-weight: bold;'
            
            # تنسيق مستوى التهديد
            if row['⚠️ Threat'] == 'CRITICAL':
                styles[3] = f'color: #dc3545; font-weight: bold;'
            elif row['⚠️ Threat'] == 'HIGH':
                styles[3] = f'color: #ffc107; font-weight: bold;'
            elif row['⚠️ Threat'] == 'MEDIUM':
                styles[3] = f'color: #17a2b8;'
            elif row['⚠️ Threat'] == 'LOW':
                styles[3] = f'color: #6b8cbf;'
            elif row['⚠️ Threat'] == 'INFO':
                styles[3] = f'color: #28a745;'
                
            return styles
        
        # ✅ تطبيق التنسيق
        styled_df = df.style.apply(style_row, axis=1)
        
        st.dataframe(
            styled_df,
            hide_index=True,
            use_container_width=True,
            column_order=['⏰ Time', '🛡️ Type', '🌐 IP', '⚠️ Threat', '⏱️ Duration', '📋 Reason']
        )
        
        # ✅ إضافة إحصائيات سريعة
        total_incidents = len(incidents)
        temp_bans = len([i for i in incidents if 'Timeout' in i['🛡️ Type']])
        perm_bans = len([i for i in incidents if 'Permanent' in i['🛡️ Type']])
        captcha_success = len([i for i in incidents if 'Success' in i['🛡️ Type']])
        
        st.markdown(f"""
        <div style="background: #2d2d2d; padding: 15px; border-radius: 10px; margin-top: 10px;">
            <h4 style="color: #e0e0e0; margin-bottom: 10px;">📈 Incident Summary (Last {total_incidents} events):</h4>
            <div style="display: grid; grid-template-columns: 1fr 1fr 1fr 1fr; gap: 15px; text-align: center;">
                <div>
                    <div style="color: #ffc107; font-size: 1.5rem; font-weight: bold;">{temp_bans}</div>
                    <div style="color: #aaa; font-size: 0.9rem;">Temporary Bans</div>
                </div>
                <div>
                    <div style="color: #dc3545; font-size: 1.5rem; font-weight: bold;">{perm_bans}</div>
                    <div style="color: #aaa; font-size: 0.9rem;">Permanent Blocks</div>
                </div>
                <div>
                    <div style="color: #17a2b8; font-size: 1.5rem; font-weight: bold;">{len([i for i in incidents if 'Honeypot' in i['🛡️ Type']])}</div>
                    <div style="color: #aaa; font-size: 0.9rem;">Honeypot Triggers</div>
                </div>
                <div>
                    <div style="color: #28a745; font-size: 1.5rem; font-weight: bold;">{captcha_success}</div>
                    <div style="color: #aaa; font-size: 0.9rem;">CAPTCHA Success</div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.info("No recent security incidents recorded. System is quiet...")

def refresh_button():
    if st.button("🔄 Refresh Data", type="primary", use_container_width=True):
        st.rerun()

def main():
    # Sidebar controls - الآن يمكننا وضع رسائل التنبيه هنا بأمان
    with st.sidebar:
        st.markdown("## 🔧 Controls")
        refresh_button()
        
        st.markdown("### 📊 Dashboard Settings")
        auto_refresh = st.checkbox("Auto-refresh (30s)", value=True)
        
        st.markdown("### 📁 File Status")
        if not STATS_FILE:
            st.warning("stats.json not found. Checked paths: " + ", ".join([str(x) for x in possible_paths if x]))
        else:
            st.info(f"Using stats file: {STATS_FILE}")
        
        st.markdown("### 📁 Debug Info")
        st.markdown(f"**Stats File:** `{STATS_FILE if STATS_FILE else 'Not Found'}`")
        st.markdown(f"**Checked Paths:** {', '.join([str(x) for x in possible_paths if x])}")
    
    # Auto-refresh every 30 seconds if enabled
    if auto_refresh:
        time.sleep(30)
        st.rerun()
    
    # Main loading loop
    data = load_data()
    if not data:
        st.info("⏳ Waiting for initial analysis data from FlexiWAF...")
        st.stop()
    
    # Display dashboard sections
    display_summary(data)
    st.divider()
    
    col1, col2 = st.columns([2, 1])
    with col1:
        display_attack_types(data)
    with col2:
        display_top_attackers(data)
    
    st.divider()
    
    # ✅ إضافة قسم تحليل الكابتشا الجديد
    display_captcha_analytics(data)
    st.divider()
    
    col1, col2 = st.columns([1, 1])
    with col1:
        display_hourly_attacks(data)
    with col2:
        display_security_incidents(data)
    
    # Footer with last updated time
    last_updated = data.get('last_updated', 'N/A')
    try:
        formatted_time = datetime.fromisoformat(last_updated.replace('Z', '+00:00')).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        formatted_time = last_updated
    
    st.markdown(f"""
    <div class="footer">
        <p>FlexiWAF Security Dashboard • Last Updated: {formatted_time}</p>
        <p style="font-size: 0.9rem; color: #888;">Real-time threat monitoring and analysis system</p>
    </div>
    """, unsafe_allow_html=True)
    
    # About section in expander
    with st.expander("ℹ️ About FlexiWAF"):
        st.markdown("""
        ### 🛡️ **FlexiWAF - Next Generation Web Application Firewall**
        
        **Advanced Security Features:**
        - ✅ **Intelligent Rate Limiting:** Blocks bots while allowing legitimate users
        - ✅ **Multi-Path Honeypots:** Detects scanners targeting admin, wp-admin, phpmyadmin, and more
        - ✅ **CAPTCHA Challenges:** Human verification after suspicious activity
        - ✅ **Dynamic IP Blocking:** Temporary and permanent IP blocking
        - ✅ **Real-time Analytics:** Live attack monitoring and threat assessment
        
        **Key Improvements in This Version:**
        - 🎯 **Enhanced Ban Type Differentiation:** Clear distinction between temporary and permanent bans
        - 🔢 **Accurate CAPTCHA Counting:** Precise attempt tracking and analytics
        - 📊 **Comprehensive Dashboard:** Modern UI with detailed security insights
        - ⚡ **Performance Optimized:** Efficient log processing with minimal overhead
        
        **How It Works:**
        1. **Detection:** Monitors traffic patterns and malicious behavior
        2. **Challenge:** Presents CAPTCHA to suspicious clients
        3. **Blocking:** Temporarily or permanently blocks confirmed attackers
        4. **Analysis:** Provides detailed security insights
        
        This dashboard provides a comprehensive view of your web application's security posture.
        """)
        
        # System status indicators
        st.subheader("📈 System Status")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("🛡️ WAF Status", "Active", "Protected")
        with col2:
            st.metric("📊 Analyzer", "Running", "Processing logs")
        with col3:
            st.metric("🔄 Data Freshness", "Real-time", "Updated every 10s")

if __name__ == "__main__":
    main()
