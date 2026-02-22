#!/bin/bash
echo ""
echo "======================================================"
echo "  ClatScope Web - OSINT Tool"
echo "======================================================"
echo ""
echo "  Starting server at: http://localhost:5000"
echo "  Press Ctrl+C to stop"
echo ""
cd "$(dirname "$0")/webapp"
python3.11 app.py
