#!/bin/bash

# AI-Enhanced Security Scanner Setup Script

echo "🚀 Setting up AI-Enhanced Security Scanner"
echo "=========================================="

# Check Python version
echo -n "Checking Python version... "
if command -v python3 &>/dev/null; then
    python_version=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    if (( $(echo "$python_version >= 3.8" | bc -l) )); then
        echo "✅ Python $python_version"
    else
        echo "❌ Python 3.8+ required (found $python_version)"
        exit 1
    fi
else
    echo "❌ Python 3 not found"
    exit 1
fi

# Create virtual environment
echo -n "Creating virtual environment... "
python3 -m venv venv
if [ $? -eq 0 ]; then
    echo "✅"
else
    echo "❌ Failed"
    exit 1
fi

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
echo -n "Upgrading pip... "
pip install --upgrade pip > /dev/null 2>&1
echo "✅"

# Install requirements
echo "Installing Python dependencies..."
pip install -r requirements.txt

# Check Ollama
echo -n "Checking Ollama installation... "
if command -v ollama &>/dev/null; then
    echo "✅"
    
    # Pull Llama2 model
    echo "Pulling Llama2 model (this may take a while)..."
    ollama pull llama2
else
    echo "❌"
    echo "⚠️  Ollama not found. AI features will be disabled."
    echo "   Install Ollama from: https://ollama.ai"
fi

# Create necessary directories
echo "Creating project directories..."
mkdir -p reports logs temp

# Make scripts executable
chmod +x scripts/*.sh

echo ""
echo "✅ Setup complete!"
echo ""
echo "Next steps:"
echo "  1. Activate virtual environment: source venv/bin/activate"
echo "  2. Start test app: python tests/test_vulnerable_app.py"
echo "  3. Run scanner: python src/main_scanner.py http://localhost:8080"
echo ""
echo "Or using Docker:"
echo "  docker-compose -f docker/docker-compose.yml up"