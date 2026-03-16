#!/bin/bash

# Quick scan runner script

# Activate virtual environment if it exists
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Default target
TARGET=${1:-"http://localhost:8080"}
INTENSITY=${2:-"medium"}

echo "🔍 Scanning target: $TARGET"
echo "📊 Intensity: $INTENSITY"
echo ""

# Run the scanner
python src/main_scanner.py "$TARGET" --intensity "$INTENSITY" ${@:3}