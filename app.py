import streamlit as st
import pandas as pd
from utils import get_baseline_model, analyze_url, analyze_content, scrape_website_content
import plotly.express as px

# Page config
st.set_page_config(
    page_title="Web Crime Detection Scanner",
    page_icon="🛡️",
    layout="wide"
)

# Custom CSS
st.markdown("""
<style>
    .reportview-container { background: #0f172a; }
    .stTextInput>div>div>input, .stTextArea>div>div>textarea {
        background-color: #1e293b; color: white; border: 1px solid #334155;
    }
    .status-card { padding: 20px; border-radius: 10px; text-align: center; margin-bottom: 20px; }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ Web Based Crime Detection")
st.markdown("### Deep URL Scanner & Content Analysis")
st.divider()

# Load Model
model = get_baseline_model()

# Main Tabs
tab_scanner, tab_content, tab_trends = st.tabs(["🔗 URL Scanner", "📝 Text Analyzer", "📈 Global Trends"])

with tab_scanner:
    col1, col2 = st.columns([2, 1])
    with col1:
        st.subheader("🔍 Analyze a Website URL")
        url_input = st.text_input("Enter Website URL", placeholder="https://...", key="url_input")
        deep_scan = st.checkbox("🔍 Enable Deep Content Scan (Scrapes Website Content)", value=True)
        
        if st.button("🚀 Start Security Scan", key="scan_btn"):
            if url_input:
                # 1. URL Structural Analysis
                with st.spinner("Analyzing URL structure..."):
                    url_result = analyze_url(url_input, model)
                    
                # 2. Scrape and Content Analysis (if enabled)
                scraped_data = None
                content_result = None
                if deep_scan:
                    with st.spinner("Scraping and analyzing website content for crimes..."):
                        scraped_data = scrape_website_content(url_input)
                        if "error" not in scraped_data:
                            content_result = analyze_content(scraped_data['text'])
                
                # Result Display
                st.subheader("🏁 Final Security Report")
                res_col1, res_col2 = st.columns(2)
                
                with res_col1:
                    st.write("**URL Risk Level:**")
                    st.markdown(f"""
                    <div class="status-card" style="background-color: {url_result['color']}22; border: 2px solid {url_result['color']};">
                        <h3 style="color: {url_result['color']};">{url_result['status'].upper()}</h3>
                        <p>Confidence: {url_result['confidence']*100:.1f}%</p>
                    </div>
                    """, unsafe_allow_html=True)
                
                with res_col2:
                    st.write("**Content Risk Level:**")
                    if content_result:
                        st.markdown(f"""
                        <div class="status-card" style="background-color: {content_result['color']}22; border: 2px solid {content_result['color']};">
                            <h3 style="color: {content_result['color']};">{content_result['status'].upper()}</h3>
                            <p>Aggregated Crime Score: {content_result['score']}</p>
                        </div>
                        """, unsafe_allow_html=True)
                    else:
                        st.info("Deep scan skipped or failed.")

                # Detailed Findings
                if content_result and content_result['findings']:
                    st.warning("⚠️ **Suspicious Material Detected on Website:**")
                    for category, detail in content_result['findings'].items():
                        st.markdown(f"- **{category}**: Detected {detail['count']} flags (e.g., {', '.join(detail['matches'][:5])})")
                elif content_result:
                    st.success("✅ No criminal content patterns detected on the webpage.")

                with st.expander("🔬 View Detailed URL Features"):
                    st.table(pd.DataFrame(list(url_result['features'].items()), columns=['Feature', 'Value']))
            else:
                st.warning("Please enter a URL to scan.")

    with col2:
        st.subheader("💡 Detection Scope")
        st.write("- **Nudity & Sexual Crimes**: Detects explicit keywords and adult material flags.")
        st.write("- **Phishing Patterns**: Structural URL analysis.")
        st.write("- **Illegal Goods**: Checks for mentions of weapons, drugs, etc.")

with tab_content:
    st.subheader("📝 Manual Content Analyzer")
    content_input = st.text_area("Paste text to analyze manually", height=150)
    if st.button("🕵️ Analyze Text"):
        if content_input:
            analysis = analyze_content(content_input)
            st.markdown(f"""<div style="padding:15px; border-radius:10px; background:{analysis['color']}22; border:1px solid {analysis['color']}; color:{analysis['color']}; text-align:center;">
                <h3>{analysis['status']} (Score: {analysis['score']})</h3></div>""", unsafe_allow_html=True)
            if analysis['findings']:
                for cat, det in analysis['findings'].items():
                    st.write(f"🚩 **{cat}**: {', '.join(det['matches'])}")
        else:
            st.warning("Please enter text.")

with tab_trends:
    st.subheader("📈 Recent Crime Detections")
    data = {'Category': ['Sexual Content', 'Fraud', 'Phishing', 'Bullying'], 'Percentage': [40, 25, 20, 15]}
    st.plotly_chart(px.pie(data, names='Category', values='Percentage', hole=0.5), use_container_width=True)

st.sidebar.info("Web Based Crime Detection v2.0 - Deep Scan Enabled.")
