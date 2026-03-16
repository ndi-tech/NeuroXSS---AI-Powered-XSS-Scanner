# NeuroXSS - AI-Powered XSS Scanner

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![Ollama](https://img.shields.io/badge/ollama-phi-green.svg)

NeuroXSS is an intelligent XSS scanner that leverages local AI models (via Ollama) to detect Cross-Site Scripting vulnerabilities with higher accuracy and fewer false positives.

## ✨ Features

- 🤖 **AI-Powered Analysis**: Uses phi model to verify potential XSS findings
- 🔍 **Automated Form Discovery**: Crawls target pages for input points
- 💉 **Comprehensive Payloads**: Tests with 50+ XSS payloads including encoded variants
- 📊 **Detailed Reports**: Generates JSON reports with AI analysis
- 🚀 **Lightweight**: No API keys needed, runs entirely locally

## 🚀 Quick Start

### Prerequisites
```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh  # Linux/Mac
# or download from https://ollama.com/download  # Windows

# Pull the phi model
ollama pull phi

Installation
bash
# Clone the repository
git clone https://github.com/ndi-tech/NeuroXSS---AI-Powered-XSS-Scanner.git
cd NeuroXSS

# Install dependencies
pip install requests beautifulsoup4

# Run the scanner
python neuroxss_scanner.py http://testphp.vulnweb.com
📖 Usage Examples
bash
# Basic scan
python neuroxss_scanner.py http://localhost:5000

# Scan with verbose output (add print statements)
python neuroxss_scanner.py http://testphp.vulnweb.com

# Results are saved to neuroxss_scan_TIMESTAMP.json
📊 Sample Output
text
╔══════════════════════════════════════════════════════════╗
║                   NeuroXSS Scanner v1.0                  ║
║            AI-Powered Cross-Site Scripting Detector      ║
╚══════════════════════════════════════════════════════════╝

Target: http://localhost:5000
AI Model: phi (available)
------------------------------------------------------------

📡 Discovering forms...
Found 4 form(s)

📝 Testing Form 1/4
  📍 Testing: http://localhost:5000/reflect
  🎯 Inputs: input
    ✅ XSS Detected!
🏗️ Architecture
text
NeuroXSS/
├── neuroxss_scanner.py    # Main scanner
├── requirements.txt        # Dependencies
├── README.md              # Documentation
└── examples/              # Example reports
🤝 Contributing
Contributions are welcome! Feel free to:

🐛 Report bugs

💡 Suggest features

🔧 Submit PRs

📝 License
MIT License - feel free to use this in your own projects!

⚠️ Disclaimer
This tool is for educational and authorized testing purposes only. Only use against systems you own or have permission to test.

text

### **`requirements.txt`**
```txt
requests>=2.28.0
beautifulsoup4>=4.11.0
.gitignore
gitignore
# Python
__pycache__/
*.py[cod]
*.so
.Python
venv/
env/
ENV/

# Scan results
*.json
!example_report.json

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db
Step 3: Initialize Git Repository
powershell
# Navigate to your project
cd C:\Users\pc\Documents\Projects Code\NeuroXSS

# Initialize git
git init

# Create the files above
# (Copy the code I provided into new files)

# Add all files
git add .

# Commit
git commit -m "Initial release: NeuroXSS AI-powered XSS scanner"

# Create GitHub repo (via website) then:
git remote add origin https://github.com/ndi-tech/NeuroXSS---AI-Powered-XSS-Scanner.git
git push -u origin main
Step 4: Create GitHub Repository
Go to https://github.com/new

Repository name: NeuroXSS

Description: "AI-Powered XSS Scanner using Local LLMs"

Public or Private (your choice)

Don't initialize with README (we have one)

Click "Create repository"

Step 5: Push to GitHub
powershell
# After creating the repo, run:
git remote add origin https://github.com/ndi-tech/NeuroXSS---AI-Powered-XSS-Scanner.git
git branch -M main
git push -u origin main
