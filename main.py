import streamlit as st
import re
import secrets
import string
from password_strength import PasswordStats
import hashlib
import requests
from datetime import datetime, timedelta
import pandas as pd
import plotly.express as px
import numpy as np
# ========================
# 🌍 MULTI-LANGUAGE SUPPORT (English + Urdu)
# ========================
LANGUAGES = {
    'en': {
        'title': '🔐✨ Password Guardian Pro 🛡️💪',
        'analyze_tab': '🔍 Password Analysis',
        'generate_tab': '🛠 Password Generator',
        'enter_password': 'Enter password to analyze:',
        'analyze_btn': 'Analyze Now 🔎',
        'strength_overview': '🔰 Strength Overview',
        'length': '📏 Length',
        'entropy': '🔑 Entropy',
        'breach_check': '🌐 Breach Check',
        'improvement_suggestions': '🛠️ Improvement Suggestions',
        'technical_details': '🔬 Technical Details',
        'generate_password': 'Generate Password 🚀',
        'password_length': 'Password Length',
        'uppercase': 'Uppercase (A-Z)',
        'numbers': 'Numbers (0-9)',
        'symbols': 'Symbols (!@#...)',
        'history_title': '📜 Analysis History',
        'about_title': 'ℹ️ About This App',
        'security_tips': '💡 Pro Security Tips',
        'security_notice': '🔒 Security Notice',
        'made_with': 'Made with ❤️ by Aamna Ashraf Rajput',
        'report_issue': 'Report Issue',
        'sharing_warning': '🚨 Never share passwords through email/social media!',
        'accessibility': '♿ Screen Reader Optimized',
        'breach_btn': 'Check Breach Status 🌐',
        'theme_toggle': '🌓 Theme',
        'health_check': '🩺 Password Health Check',
        'expiry_reminder': '⏰ Password Expiry Reminder',
        'leaderboard': '🏆 Password Strength Leaderboard',
        'clear_history': '🗑️ Clear All History',
        'heatmap_title': '🔥 Character Distribution Heatmap',
        'radar_title': '📊 Password Strength Radar',
        'requirements': '🛠️ Requirements'  
    },
    'ur': {
        'title': '🔐✨ پاس ورڈ گارڈین 🛡️💪',
        'analyze_tab': '🔍 پاس ورڈ کا تجزیہ',
        'generate_tab': '🛠 پاس ورڈ جنریٹر',
        'enter_password': 'تجزیہ کے لیے پاس ورڈ درج کریں:',
        'analyze_btn': 'ابھی تجزیہ کریں 🔎',
        'strength_overview': '🔰 طاقت کا جائزہ',
        'length': '📏 لمبائی',
        'entropy': '🔑 اینٹروپی',
        'breach_check': '🌐 بریچ چیک',
        'improvement_suggestions': '🛠️ بہتری کے مشورے',
        'technical_details': '🔬 تکنیکی تفصیلات',
        'generate_password': 'پاس ورڈ بنائیں 🚀',
        'password_length': 'پاس ورڈ کی لمبائی',
        'uppercase': 'بڑے حروف (A-Z)',
        'numbers': 'نمبر (0-9)',
        'symbols': 'علامات (!@#...)',
        'history_title': '📜 تجزیہ کی تاریخ',
        'about_title': 'ℹ️ ایپ کے بارے میں',
        'security_tips': '💡 پیشہ ورانہ حفاظتی تجاویز',
        'security_notice': '🔒 سیکورٹی نوٹس',
          'made_with': 'آمنہ اشرف کی طرف سے ❤️ کے ساتھ بنایا گیا',
        'report_issue': 'مسئلہ رپورٹ کریں',
        'sharing_warning': '🚨 ای میل/سوشل میڈیا کے ذریعے پاس ورڈ شیئر نہ کریں!',
        'accessibility': '♿ اسکرین ریڈر کے لیے موزوں',
        'breach_btn': 'بریچ کی حیثیت چیک کریں 🌐',
        'theme_toggle': '🌓 تھیم',
        'health_check': '🩺 پاس ورڈ ہیلتھ چیک',
        'expiry_reminder': '⏰ پاس ورڈ کی میعاد ختم ہونے کی یاددہانی',
        'leaderboard': '🏆 پاس ورڈ طاقت کی لیڈر بورڈ',
        'clear_history': '🗑️ تمام تاریخ صاف کریں',
        'heatmap_title': '🔥 کریکٹر تقسیم ہیٹ میپ',
        'radar_title': '📊 پاس ورڈ طاقت ریڈار',
        'requirements': '🛠️ ضروریات'  
    }
}
# ========================
# 🎨 THEME-ADAPTIVE STYLING
# ========================
st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Roboto+Mono:wght@300;500&display=swap');
    
    [data-theme="light"] {
        --primary: #2ecc71;
        --secondary: #3498db;
        --danger: #e74c3c;
        --text: #2c3e50;
        --background: #ffffff;
    }
    
    [data-theme="dark"] {
        --primary: #27ae60;
        --secondary: #2980b9;
        --danger: #c0392b;
        --text: #ecf0f1;
        --background: #1a1a1a;
    }
    
    [data-testid="stAppViewContainer"] {
        background: var(--background);
        font-family: 'Roboto Mono', monospace;
    }
    
    .title-text {
        font-size: 2.5rem !important;
        color: var(--text) !important;
        text-align: center;
        margin-bottom: 10px !important;
        font-weight: 500 !important;
        background: linear-gradient(45deg, var(--primary), var(--secondary));
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    
    .metric-box {
        padding: 15px;
        border-radius: 10px;
        margin: 10px 0;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }
    
    [data-theme="light"] .metric-box {
        background: rgba(255, 255, 255, 0.9);
    }
    
    [data-theme="dark"] .metric-box {
        background: rgba(0, 0, 0, 0.2);
    }
    
    .strength-bar {
        height: 15px;
        border-radius: 8px;
        transition: all 0.3s ease;
    }
    
    .password-history {
        border-left: 3px solid var(--primary);
        padding-left: 15px;
        margin: 15px 0;
    }
    
    .generated-password {
        font-size: 1.2rem;
        letter-spacing: 2px;
        padding: 10px;
        background: rgba(var(--primary), 0.1);
        border-radius: 5px;
        margin: 10px 0;
    }
    
    </style>
""", unsafe_allow_html=True)

# ========================
# 🌟 MAIN HEADING WITH EMOJIS AND BOX DESIGN
# ========================
st.markdown(f"""
    <div style="
        text-align: center;
        padding: 20px;
        border-radius: 15px;
        background: linear-gradient(145deg, #2ecc71, #3498db);
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
        margin-bottom: 10px;
    ">
        <h1 class="title-text" style="
            font-size: 2.8rem;
            color: white;
            margin: 0;
            padding: 10px;
        ">
            🔐✨ <span style="
                background: linear-gradient(45deg, #ffffff, #f1c40f);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
            ">
            Password Guardian</span> 🛡️💪
        </h1>
        <p style="
            color: rgba(255, 255, 255, 0.9);
            font-size: 1.2rem;
            margin: 0;
            padding: 5px;
        ">
            🚀 Your Ultimate Password Guardian 🛡️ | 🔒 Secure | ⚡ Fast | 🌍 Global
        </p>
    </div>
""", unsafe_allow_html=True)

# ========================
# 🔒 SECURITY FUNCTIONS
# ========================
def check_pwned(password):
    sha1hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1hash[:5], sha1hash[5:]
    try:
        response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=3)
        return any(line.split(':')[0] == suffix for line in response.text.splitlines())
    except:
        return False

def generate_password(length=12, uppercase=True, numbers=True, symbols=True):
    characters = string.ascii_lowercase
    if uppercase: characters += string.ascii_uppercase
    if numbers: characters += string.digits
    if symbols: characters += string.punctuation
    
    while True:
        password = ''.join(secrets.choice(characters) for _ in range(length))
        if (sum(c.islower() for c in password) >= 1 and
            (not uppercase or sum(c.isupper() for c in password) >= 1) and
            (not numbers or sum(c.isdigit() for c in password) >= 1) and
            (not symbols or any(c in string.punctuation for c in password))):
            return password

def get_strength_details(password):
    stats = PasswordStats(password)
    feedback = []
    
    strength = stats.strength()
    if strength < 0.3:
        strength_color = "#e74c3c"
        strength_label = "Weak 🔴"
    elif strength < 0.6:
        strength_color = "#f1c40f"
        strength_label = "Medium 🟡"
    else:
        strength_color = "#2ecc71"
        strength_label = "Strong 🟢"
    
    if len(password) < 12:
        feedback.append("🚨 Consider making password longer (12+ characters)")
    if not any(c.isupper() for c in password):
        feedback.append("✨ Add uppercase letters")
    if not any(c.isdigit() for c in password):
        feedback.append("🔢 Include numbers")
    if not any(c in string.punctuation for c in password):
        feedback.append("⚡ Add special characters")
    if password.lower() == password:
        feedback.append("🌀 Mix uppercase and lowercase letters")
    
    entropy = stats.entropy_bits
    
    return {
        'strength': strength,
        'strength_label': strength_label,
        'strength_color': strength_color,
        'length': len(password),
        'entropy': f"{entropy:.1f} bits",
        'feedback': feedback,
        'hash_sha256': hashlib.sha256(password.encode()).hexdigest()
    }

# ========================
# 🚀 APP INITIALIZATION
# ========================
if 'history' not in st.session_state:
    st.session_state.history = []
if 'last_analyzed' not in st.session_state:
    st.session_state.last_analyzed = None
if 'last_breach_check' not in st.session_state:
    st.session_state.last_breach_check = ('', '')
if 'leaderboard' not in st.session_state:
    st.session_state.leaderboard = []  # Initialize leaderboard
if 'generated_passwords' not in st.session_state:
    st.session_state.generated_passwords = []

# ========================
# 🖥 SIDEBAR CONFIGURATION
# ========================
with st.sidebar:
    language = st.selectbox("🌍 زبان / Language", ['en', 'ur'], format_func=lambda x: "English" if x == 'en' else "اردو")
    st.markdown(f"**{LANGUAGES[language]['theme_toggle']}**")
    st.markdown(LANGUAGES[language]['accessibility'])

    # Password Expiry Reminder
    st.markdown(f"### {LANGUAGES[language]['expiry_reminder']}")
    if st.session_state.generated_passwords:
        for idx, (password, timestamp) in enumerate(st.session_state.generated_passwords):
            expiry_date = timestamp + timedelta(days=90)
            days_left = (expiry_date - datetime.now()).days
            if days_left > 0:
                st.warning(f"Password {idx + 1} expires in {days_left} days")
            else:
                st.error(f"Password {idx + 1} expired {abs(days_left)} days ago")

    # Password Strength Leaderboard
    st.markdown(f"### {LANGUAGES[language]['leaderboard']}")
    if st.session_state.leaderboard:
        leaderboard_df = pd.DataFrame(st.session_state.leaderboard)
        st.dataframe(leaderboard_df)
    else:
        st.info("No passwords analyzed yet. Analyze a password to see the leaderboard.")




# ========================
# � MAIN APP INTERFACE
# ========================
tab1, tab2 = st.tabs([LANGUAGES[language]['analyze_tab'], LANGUAGES[language]['generate_tab']])

with tab1:
    st.warning(LANGUAGES[language]['sharing_warning'])
    password_input = st.text_input(LANGUAGES[language]['enter_password'], type="password")
    
    if password_input:
        analysis = get_strength_details(password_input)
        
        # Store analysis results in session state
        st.session_state.analysis = analysis
        st.session_state.last_analyzed = password_input
        
        # Add to history
        st.session_state.history.insert(0, {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'password': password_input[:2] + '***' + password_input[-2:],
            'strength': analysis['strength_label']
        })
        st.session_state.history = st.session_state.history[:10]
        
        # Update leaderboard
        st.session_state.leaderboard.append({
            "Password": password_input[:2] + '***' + password_input[-2:],  # Masked password
            "Strength": analysis['strength'],  # Strength score
            "Entropy": float(analysis['entropy'].split()[0]),  # Entropy value
            "Length": analysis['length']  # Password length
        })
        
        # Keep only the top 5 strongest passwords
        st.session_state.leaderboard = sorted(
            st.session_state.leaderboard,
            key=lambda x: x['Strength'],
            reverse=True
        )[:5]
        
        # Display analysis results
        st.markdown(f"""
        <div class="metric-box">
            <h3>{LANGUAGES[language]['strength_overview']}</h3>
            <div style="color: {analysis['strength_color']}; font-size: 1.4rem;">
                {analysis['strength_label']}
            </div>
            <div class="strength-bar" style="width: {analysis['strength']*100}%; 
                background: {analysis['strength_color']}; margin: 10px 0;"></div>
            <div>{LANGUAGES[language]['length']}: {analysis['length']} characters</div>
            <div>{LANGUAGES[language]['entropy']}: {analysis['entropy']}</div>
        </div>
        """, unsafe_allow_html=True)
        
        # Progress Bar Visualization
        st.markdown(f"**Progress Bar**")
        st.progress(analysis['strength'])
        
         # Breach Check
        if st.button(LANGUAGES[language]['breach_btn']):
            pwned = check_pwned(password_input)
            st.session_state.last_breach_check = (
                password_input,
                "⚠️ Compromised (Found in breaches)" if pwned else "✅ Not found in breaches"
            )
        
        if st.session_state.last_breach_check[0] == password_input:
            st.markdown(f"""
            <div class="metric-box">
                <div>{LANGUAGES[language]['breach_check']}: {st.session_state.last_breach_check[1]}</div>
            </div>
            """, unsafe_allow_html=True)
        
        # Improvement Suggestions
        if analysis['feedback']:
            st.markdown(f"""
            <div class="metric-box">
                <h3>{LANGUAGES[language]['improvement_suggestions']}</h3>
                <ul style="list-style-type: none; padding-left: 0;">
            """, unsafe_allow_html=True)
            for item in analysis['feedback']:
                st.markdown(f"<li>📌 {item}</li>", unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)
        
        # Technical Details
        with st.expander(LANGUAGES[language]['technical_details']):
            st.write(f"SHA-256 Hash: `{analysis['hash_sha256']}`")
            st.code(f"Entropy Calculation: {analysis['entropy']}")

        # Heatmap Visualization
        st.markdown(f"### {LANGUAGES[language]['heatmap_title']}")
        char_counts = {char: password_input.count(char) for char in set(password_input)}
        heatmap_data = pd.DataFrame(list(char_counts.items()), columns=["Character", "Count"])
        fig = px.bar(heatmap_data, x="Character", y="Count", color="Count", 
                     title="Character Distribution Heatmap")
        st.plotly_chart(fig)


# Radar Chart Visualization (inside the if password_input block)
if password_input:
    st.markdown(f"### {LANGUAGES[language]['radar_title']}")

    # Calculate metrics for the radar chart
    metrics = {
        'Length': min(analysis['length'] / 32, 1.0),  # Normalize length (max 32 chars)
        'Entropy': min(float(analysis['entropy'].split()[0]) / 128, 1.0),  # Normalize entropy (max 128 bits)
        'Strength': analysis['strength'],
        'Diversity': len(set(password_input)) / len(password_input),  # Character diversity
        'Breach Status': 0 if check_pwned(password_input) else 1  # 0 = breached, 1 = safe
    }

    # Create radar chart data
    radar_data = pd.DataFrame(dict(
        r=list(metrics.values()),
        theta=list(metrics.keys())
    ))

    # Plot radar chart
    fig = px.line_polar(radar_data, r='r', theta='theta', line_close=True, 
                        color_discrete_sequence=['#2ecc71'],  # Green color for the chart
                        title="Password Strength Metrics")

    # Update layout for better visualization
    fig.update_traces(fill='toself')
    fig.update_layout(
        polar=dict(
            radialaxis=dict(
                visible=True,
                range=[0, 1]  # Set range from 0 to 1
            )
        ),
        showlegend=False
    )

    # Display the radar chart
    st.plotly_chart(fig)

with tab2:
    with st.form("password_generator"):
        col1, col2 = st.columns(2)
        with col1:
            length = st.slider(LANGUAGES[language]['password_length'], 8, 32, 16)
        with col2:
            uppercase = st.checkbox(LANGUAGES[language]['uppercase'], True)
            numbers = st.checkbox(LANGUAGES[language]['numbers'], True)
            symbols = st.checkbox(LANGUAGES[language]['symbols'], True)
        
        generate_btn = st.form_submit_button(LANGUAGES[language]['generate_password'])
        
        if generate_btn:
            generated_pw = generate_password(length, uppercase, numbers, symbols)
            st.session_state.generated_passwords.append((generated_pw, datetime.now()))
            st.markdown(f"""
            <div class="generated-password">
                🔒 {generated_pw}
                <button onclick="navigator.clipboard.writeText('{generated_pw}')" 
                    style="float: right; background: var(--secondary); color: white; border: none; padding: 5px 10px; border-radius: 5px;">
                    Copy 📋
                </button>
            </div>
            """, unsafe_allow_html=True)

# ========================
# 📜 HISTORY SECTION WITH WORKING BUTTONS
# ========================
st.markdown(f"### {LANGUAGES[language]['history_title']}")

if st.session_state.history:
    # Create columns for history display and removal
    col1, col2 = st.columns([4, 1])
    
    with col1:
        for idx, item in enumerate(st.session_state.history):
            st.markdown(f"""
            <div class="password-history">
                <div style="color: var(--text); font-size: 0.9rem;">
                    📅 {item['timestamp']} - {item['password']} 
                    <span style="float: right; color: {{
                        'Weak 🔴': '#e74c3c',
                        'Medium 🟡': '#f1c40f',
                        'Strong 🟢': '#2ecc71'
                    }}[item['strength']]">
                        {item['strength']}
                    </span>
                </div>
            </div>
            """, unsafe_allow_html=True)
    
    with col2:
        st.write("")  # Spacer
        st.write("")  # Spacer
        
        # Clear All Button
        if st.button(LANGUAGES[language]['clear_history'], key="clear_all"):
            # Clear the history and reset last_analyzed
            st.session_state.history = []
            st.session_state.last_analyzed = None
            st.session_state.clear()  # Optional: Clear all session state
            st.rerun()  # Force rerun to update UI
else:
    st.info("No password analysis history yet. Analyze a password to see history here.")

# ========================
# ℹ️ ADDITIONAL INFORMATION
# ========================
with st.expander(LANGUAGES[language]['about_title']):
    st.markdown(f"## 🌟 {LANGUAGES[language]['security_tips']}")
    st.markdown("""
    - Use password managers like Bitwarden
    - Enable 2FA everywhere
    - Never reuse passwords
    - Change passwords after breaches
    - Use biometric authentication where available
    """)
    
    st.markdown(f"## {LANGUAGES[language]['security_notice']}")
    st.markdown("""
    This app runs locally in your browser - passwords are never stored or transmitted.
    All cryptographic operations are performed client-side.
    """)

# ========================
# 🛠️ REQUIREMENTS & FOOTER
# ========================


st.markdown("---")
st.markdown(f"""
    <div style="text-align: center; color: var(--text); font-size: 0.8rem;">
        {LANGUAGES[language]['made_with']} | 🔐 Stay Secure | 
        <a href="#" style="color: var(--primary); text-decoration: none;">{LANGUAGES[language]['report_issue']}</a>
    </div>
""", unsafe_allow_html=True)