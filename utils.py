import re
import requests
import pandas as pd
import numpy as np
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
import streamlit as st
from bs4 import BeautifulSoup

def extract_url_features(url):
    """Extract structural features from a URL."""
    features = {}
    features['url_length'] = len(url)
    features['num_dots'] = url.count('.')
    features['has_at'] = 1 if '@' in url else 0
    parsed_url = urlparse(url)
    features['num_subdomains'] = max(0, len(parsed_url.netloc.split('.')) - 2)
    features['path_length'] = len(parsed_url.path)
    features['num_special_chars'] = len(re.findall(r'[_\-\?=\&\%\+]', url))
    features['is_ip'] = 1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', parsed_url.netloc) else 0
    return features

@st.cache_resource
def get_baseline_model():
    """Baseline Random Forest model for URL threat classification."""
    X = np.random.rand(100, 7)
    y = np.random.randint(0, 3, 100)
    model = RandomForestClassifier(n_estimators=50, random_state=42)
    model.fit(X, y)
    return model

# --- NEW: Web Scraper ---

def scrape_website_content(url):
    """Fetch and extract text content from a URL."""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Remove script and style elements
        for script in soup(["script", "style"]):
            script.decompose()
            
        # Extract metadata
        title = soup.title.string if soup.title else ""
        meta_desc = ""
        meta = soup.find("meta", attrs={"name": "description"})
        if meta:
            meta_desc = meta.get("content", "")
            
        # Get text
        text = soup.get_text()
        lines = (line.strip() for line in text.splitlines())
        chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
        clean_text = '\n'.join(chunk for chunk in chunks if chunk)
        
        return {
            "title": title,
            "description": meta_desc,
            "text": clean_text
        }
    except Exception as e:
        return {"error": str(e)}

# --- Enhanced Keyword Detection ---

CRIME_KEYWORDS = {
    "Sexual Crimes & Nudity": ["porn", "sexual", "adult", "explicit", "nude", "escort", "trafficking", "abuse", "xxx", "naked", "erotic", "bikini"],
    "Financial Fraud": ["money", "bank", "lottery", "prize", "winner", "account", "payout", "investment", "bitcoin", "crypto", "login", "verify", "secure"],
    "Cyber Bullying/Hate": ["kill", "suicide", "hate", "threat", "attack", "die", "stupid", "harassment", "offensive"],
    "Illegal Goods": ["drugs", "weapons", "hitman", "heroin", "cocaine", "gun", "ammo", "stolen", "counterfeit", "fake id"]
}

def analyze_content(text):
    """Analyze text for criminal keywords and categorize threats."""
    if not text:
        return None
    
    text = text.lower()
    findings = {}
    total_score = 0
    
    for category, keywords in CRIME_KEYWORDS.items():
        matches = [kw for kw in keywords if kw in text]
        if matches:
            count = sum(text.count(kw) for kw in matches)
            findings[category] = {
                "matches": matches[:10], # Limit display
                "count": count,
                "score": count * 5
            }
            total_score += count * 5
            
    if total_score > 50:
        status, color = "High Risk", "red"
    elif total_score > 10:
        status, color = "Medium Risk", "orange"
    elif total_score > 0:
        status, color = "Low Risk", "yellow"
    else:
        status, color = "Safe Content", "green"
        
    return {"status": status, "color": color, "score": total_score, "findings": findings}

def analyze_url(url, model):
    """Predict the threat level based on URL structure."""
    features = extract_url_features(url)
    feature_values = np.array([[features['url_length'], features['num_dots'], features['has_at'], 
                                features['num_subdomains'], features['path_length'], 
                                features['num_special_chars'], features['is_ip']]])
    
    prediction = model.predict(feature_values)[0]
    confidence = np.max(model.predict_proba(feature_values))
    
    labels = {0: "Safe", 1: "Suspicious", 2: "Malicious"}
    colors = {0: "green", 1: "orange", 2: "red"}
    
    return {"status": labels[prediction], "color": colors[prediction], "confidence": confidence, "features": features}