# Web-Based Crime Prediction System

## Project Overview
The Web-Based Crime Prediction System is a web application that analyzes website URLs and text content to detect possible cybercrime risks.  
The system scans URLs, analyzes their features, and generates a security report indicating whether the website is safe or risky.  
It also provides a text analyzer to check harmful or suspicious content.

 Features

 1. URL Security Scan
- Users enter a website URL and click **Start Security Scan**.
- The system analyzes the URL and generates a **Final Security Report**.

The report includes:
- URL Risk Level (Safe or Risky)
- Content Risk Level
- Deep Scan Status (Completed / Skipped / Failed)

 2. URL Feature Analysis
Users can click **View Details** to see the URL features used for analysis.

These features include:
- URL Length
- Number of Dots
- Path Length
- Number of Special Characters
- IP Address Detection

All feature values are displayed in the final security report.

 3. Text Analyzer
Users can paste text manually and click **Analyze Text**.

The system analyzes the text and returns:
- Safe
- Risky

This helps identify harmful or suspicious content.

 4. Global Crime Trends
The application also displays statistics of recent cybercrime patterns such as:
- Phishing
- Fraud
- Bullying
- Sexual Content

This helps users understand common online threats.

*Technologies Used*
- Python
- Pandas
- NumPy
- Streamlit

## How to Run the Project

1. Install required libraries 
2. Run the application streamlit run app.py 
3. Open the local URL shown in the terminal to use the application.

* Project Output
The system provides:
- URL Security Report
- Detailed URL Feature Analysis
- Text Content Risk Detection
- Cybercrime Trend Visualization

