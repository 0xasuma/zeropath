#!/bin/bash
# ZeroPath Deploy Script

echo "🛡️ Deploying ZeroPath..."

# Install dependencies
echo "Installing Python dependencies..."
cd /root/zeropath
pip install -r requirements.txt -q

# Create systemd service
cat > /etc/systemd/system/zeropath.service << EOF
[Unit]
Description=ZeroPath - Autonomous Exploit Chain Generator
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/zeropath
ExecStart=/usr/bin/python3 /root/zeropath/backend/main.py
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

# Resource limits
MemoryMax=1G
CPUQuota=50%

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
systemctl daemon-reload
systemctl enable zeropath
systemctl restart zeropath

# Check status
sleep 2
if systemctl is-active --quiet zeropath; then
    echo "✅ ZeroPath is running on port 5002"
    systemctl status zeropath --no-pager
else
    echo "❌ Failed to start ZeroPath"
    journalctl -u zeropath --no-pager -n 20
fi
