import streamlit as st
from core.analyzer import analyze_email

st.set_page_config(
    page_title="PhishNyx AI",
    page_icon="🛡️",
    layout="centered"
)

st.title("🛡️ PhishNyx AI")
st.subheader("AI-Powered Phishing Detection Simulator")

st.markdown("Analyze suspicious emails and detect phishing threats using intelligent rules.")

# Inputs
sender = st.text_input("📧 Sender Email")
subject = st.text_input("📝 Subject")
body = st.text_area("📄 Email Body", height=200)

if st.button("🔍 Analyze Email"):
    if not body:
        st.warning("Please enter email content.")
    else:
        result = analyze_email(sender, subject, body)

        st.markdown("---")
        st.subheader("📊 Analysis Result")

        st.metric("Risk Score", f"{result['score']}/100")
        st.write(f"**Verdict:** {result['verdict']}")

        st.markdown("### 🚨 Detected Red Flags")
        for flag in result["flags"]:
            st.write(f"- {flag}")

        st.markdown("### 💡 Recommendation")
        st.write(result["recommendation"])