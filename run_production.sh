#!/bin/zsh
echo "🏭 Starting FULL Production IDS Stack"
echo "📊 Dashboard: http://localhost:5001/dashboard"
echo "👀 Auto-detect: captures/ folder"
echo "📈 Logs: supervisor_*.log"
echo "Stop: Ctrl+C then 'supervisorctl shutdown'"

supervisord -c supervisord.conf

