#!/bin/zsh
# Production: Gunicorn WSGI server (4 workers)
cd backend
gunicorn -w 4 -b 0.0.0.0:5001 app:app --log-level info

