#!/bin/zsh
echo "🚀 Starting Production IDS Dashboard..."
echo "1. Backend (with dashboard): http://localhost:5001"
echo "2. Upload CSV → Run Detection → Watch live dashboard!"

cd backend
python3 app.py

