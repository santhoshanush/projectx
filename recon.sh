#!/bin/bash

# Change interrupt key to Ctrl+X (ASCII 24)
stty intr ^X

# Trap SIGINT (now Ctrl+X)
trap "echo -e '\n\033[0;31mProcess interrupted. Exiting...\033[0m'; stty intr ^C; exit 1" SIGINT

# Files & Directories
RESULTS_FILE="scan_results.txt"
LOG_DIR="logs"
FILTERS_DIR="./filters"
mkdir -p "$LOG_DIR"
USERLIST="/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt"

# Colors
RED='\033[0;31m'    # Critical
YELLOW='\033[1;33m' # Warning
GREEN='\033[0;32m'  # Success
BLUE='\033[0;34m'   # Info
NC='\033[0m'        # No Color


# --- Main Script ---

TARGET_IP=$(grep -oP 'Nmap scan report for \K[\d\.]+' "$RESULTS_FILE" || echo "")
[[ -z "$TARGET_IP" ]] && { echo -e "${RED}No IP found. Exiting.${NC}"; exit 1; }

echo -e "${GREEN}Target IP: $TARGET_IP${NC}"
OPEN_PORTS=$(grep -oP '^\d+/tcp\s+open' "$RESULTS_FILE" | awk -F/ '{print $1}')

# Remove port 139 if 445 is open (SMB redundancy)
[[ "${OPEN_PORTS[@]}" =~ '139' && "${OPEN_PORTS[@]}" =~ '445' ]] && OPEN_PORTS=${OPEN_PORTS[@]/139/}

for port in $OPEN_PORTS; do
      LOG_FILE="$LOG_DIR/port_${port}.log"
    echo -e "\n${YELLOW}Scanning port $port...${NC}"

    case $port in
        22)
            echo -e "\n${BLUE}[+] Scanning SSH (Port 22)...${NC}"
            nmap -sV -p 22 --script=ssh2-enum-algos,ssh-auth-methods "$TARGET_IP" -oN "$LOG_DIR/ssh_scan.log" >/dev/null 2>&1
            echo -e "${GREEN}SSH Version: $(grep -oP 'ssh.*' "$LOG_DIR/ssh_scan.log" | head -1)${NC}"

            # Brute-force prompt
            read -p "$(echo -e ${YELLOW}'Run Hydra brute-force? (Y/N): '${NC})" choice
            if [[ "${choice^^}" == "Y" ]]; then
                echo -e "${RED}[!] WARNING: Brute-forcing may trigger locks!${NC}"
    
                # Run Hydra with filtered output
                hydra -L /usr/share/wordlists/metasploit/unix_users.txt \
                 -P /usr/share/wordlists/rockyou.txt \
                 ssh://"$TARGET_IP" -t 4 -vV > "$LOG_DIR/ssh_hydra.log" 2>&1
                # Show filtered results
                if [ -f "$FILTERS_DIR/filter_hydra.sh" ]; then
                    echo -e "\n${GREEN}[+] SSH Brute-Force Results:${NC}"
                    "$FILTERS_DIR/filter_hydra.sh" "$LOG_DIR/ssh_hydra.log"
                fi       
                else
                echo -e "${GREEN}Skipping brute-force.${NC}"
            fi
            ;;

        23)
        echo -e "\n${BLUE}Telnet service detected ...."
         read -p "$(echo -e ${YELLOW}'Run Hydra brute-force? (Y/N): '${NC})" choice
            if [[ "${choice^^}" == "Y" ]]; then
                echo -e "${RED}[!] WARNING: Brute-forcing may trigger locks!${NC}"
    
                # Run Hydra with filtered output
                hydra -L /usr/share/wordlists/metasploit/unix_users.txt \
                 -P /usr/share/wordlists/rockyou.txt \
                 telnet://"$TARGET_IP" -t 4 -vV > "$LOG_DIR/telnet_hydra.log" 2>&1
                # Show filtered results
                if [ -f "$FILTERS_DIR/filter_hydra.sh" ]; then
                    echo -e "\n${GREEN}[+] Telnet Brute-Force Results:${NC}"
                    "$FILTERS_DIR/filter_hydra.sh" "$LOG_DIR/telnet_hydra.log"
                fi       
            else
                echo -e "${GREEN}Skipping brute-force.${NC}"
            fi
        ;;
            
       80|443)
            # --- HTTP Scan (Port 80) ---
            echo -e "\n${BLUE}[+] Scanning HTTP(s) (Port 80 | 443)...${NC}"
            if [[ $port == 80 ]]; then
                URL="http://$TARGET_IP/"
            else 
                URL="https://$TARGET_IP/"
            fi
            # Gobuster scan
            gobuster dir -u $URL  \
            -w /usr/share/wordlists/dirb/common.txt \
             -t 50 -x php,html,txt -b 403,404 \
             -q --no-color > "$LOG_DIR/gobuster.log" 2>&1
             if [ -f "$FILTERS_DIR/filter_gobuster.sh" ]; then
                    "$FILTERS_DIR/filter_gobuster.sh" "$LOG_DIR/gobuster.log"
             fi

            # FFUF (still shows progress)
            #echo -e "${BLUE}Running FFUF...${NC}"
            #ffuf -u "${url}FUZZ" -w /usr/share/wordlists/dirb/common.txt -of csv -o "$LOG_DIR/ffuf_$port.csv" >/dev/null 2>&1
            #filter_ffuf "$LOG_DIR/ffuf_$port.csv"
            
            ;;

        3306)

            echo -e "\n${BLUE}[+] Starting MySQL Recon ..."

            # --- Phase 1: Service Detection ---
            echo -e "\n${YELLOW}[*] Verifying MySQL service...${NC}"
            nmap -p 3306 --script=mysql-info ${TARGET_IP} -oN "${LOG_DIR}/mysql_service.log" >/dev/null 2>&1

            if grep -q "mysql" "${LOG_DIR}/mysql_service.log"; then
             mysql_version=$(grep -oP "Version: \K[^\n]+" "${LOG_DIR}/mysql_service.log")
             echo -e "${GREEN}[+] MySQL Detected: ${mysql_version}${NC}"
            else
                echo -e "${RED}[-] MySQL not found on port ${MYSQL_PORT}${NC}"
            exit 1
            fi

            # --- Phase 2: Default Credential Check ---
            echo -e "\n${YELLOW}[*] Testing default MySQL credentials...${NC}"

            declare -A creds=(
                    ["root"]="root"
                    ["root"]=""
                    ["admin"]="admin"
                    ["mysql"]="mysql"
                    )   

            found_creds=false
            for user in "${!creds[@]}"; do
                echo -ne "Testing ${user}:${creds[$user]}... "
                if mysql -h ${TARGET_IP} -u ${user} -p"${creds[$user]}" -e "SELECT 1" 2>/dev/null | grep -q "1"; then
                    echo -e "${GREEN}SUCCESS${NC}"
                    echo "Valid credentials: ${user}:${creds[$user]}" >> "${LOG_DIR}/mysql_creds.log"
                    found_creds=true
                else
                    echo -e "${RED}FAILED${NC}"
                fi
            done

            if [ "$found_creds" = false ]; then
                echo -e "${YELLOW}[-] No default credentials worked${NC}"
            fi

            # --- Phase 3: SQL Injection Test ---
            echo -e "\n${YELLOW}[*] SQL Injection Testing${NC}"
            read -p "Enter URL to test for SQLi (e.g., http://target.com/page?id=1): " sqlmap_url

            if [ -n "$sqlmap_url" ]; then
                echo -e "${BLUE}[+] Running SQLMap against: ${sqlmap_url}${NC}"
                sqlmap -u "${sqlmap_url}" --batch --level=3 --risk=2 --output-dir="${LOG_DIR}/sqlmap" > "${LOG_DIR}/sqlmap.log" 2>&1
    
                echo -e "\n${GREEN}[+] SQL Injection Results:${NC}"
                if grep -q "is vulnerable" "${LOG_DIR}/sqlmap.log"; then
                    grep -A5 "is vulnerable" "${LOG_DIR}/sqlmap.log"
                    echo -e "\n${RED}[!] VULNERABLE TO SQL INJECTION${NC}"
                else
                    echo -e "${GREEN}[+] No SQL injection vulnerabilities found${NC}"
                fi
            else
                echo -e "${YELLOW}[-] Skipping SQL injection test (no URL provided)${NC}"
            fi

            swecho -e "\n${BLUE}[+] MySQL reconnaissance complete. Logs saved to ${LOG_DIR}/${NC}"
            ;;
        21)
            # FTP checks + Hydra
            echo -e "${BLUE}Checking FTP...${NC}"
            ftp -inv "$TARGET_IP" <<EOF | tee -a "$LOG_DIR/ftp.log"
user anonymous anonymous
quit
EOF
            [[ $? -eq 0 ]] && { echo -e "${RED}Anonymous FTP login allowed!${NC}"; }
            ;;
        
    #   53)
    # DNS Enumeration (Silent Wfuzz)
    #echo -e "${BLUE}[+] Running DNS Enumeration...${NC}"
    
    # 1. Reverse DNS lookup
    #domain=$(dig -x "$TARGET_IP" +short 2>/dev/null | head -n1 | sed 's/\.$//')
    #[[ -z "$domain" ]] && domain="$TARGET_IP"
    
    # 2. Wfuzz subdomain scan (silent)
    #wfuzz -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
     #     -H "Host: FUZZ.$domain" \
      #    --hc 404 \
       #   "http://$domain" > "$LOG_DIR/wfuzz_dns.log" 2>&1
    
    # 3. Show filtered results only
    #filter_wfuzz "$LOG_DIR/wfuzz_dns.log"
    #;;

        25)
        echo -e "\n${BLUE}Testing for known SMTP vulnerabilities ..."
        # VRFY command check and user enumeration using the specified userlist
        echo -e "\n${NC}Attempting user enumeration with VRFY command..."
        while IFS= read -r user; do
            VRFY_RESULT=$(echo "VRFY $user" | nc -w 5 "$TARGET_IP" 25 2>/dev/null)
            if echo "$VRFY_RESULT" | grep -qi "252"; then
                echo "[+] User '$user' exists on the SMTP server!"
            fi
        done < "$USERLIST"

        # Open relay check
        echo -e "\n${BLUE}Testing for SMTP Open Relay..."
        echo -e "\n${NC}MAIL FROM:<attacker@example.com>\nRCPT TO:<victim@example.com>\nQUIT" | nc -w 5 "$TARGET_IP" 25 2>/dev/null | grep -qi "Relaying denied"
        if [ $? -eq 0 ]; then
            echo "[+] No open relay detected – SMTP server is secure against relay abuse."
        else
            echo "[!] WARNING: SMTP server may be an open relay! Relaying not denied."
        fi

        echo -e "\n${GREEN}SMTP enumeration, user enumeration, and vulnerability scan completed!"
        ;;

        135)
        echo -e "\n${BLUE}Testing for known RPC vulnerabilities ..."
# Example vulnerability check using rpcinfo to test for specific services
        if rpcinfo -p "$TARGET_IP" | grep -q "100003"; then
            echo -e "\n${RED}[+] NFS RPC service detected (program number 100003)."
            echo -e "\n${RED}[!] Check for potential NFS-related vulnerabilities."
        fi

        if rpcinfo -p "$TARGET_IP" | grep -q "100005"; then
            echo -e "\n${RED}[+] Mountd RPC service detected (program number 100005)."
            echo -e "\n${RED}[!] Check for potential NFS mount vulnerabilities."
        fi

        if rpcinfo -p "$TARGET_IP" | grep -q "100000"; then
            echo -e "\n${RED}[+] Portmapper detected. Be cautious of potential remote exploits."
        fi

        echo -e "\nRPC service enumeration and vulnerability check completed!"
        RPC_OUTPUT=$(rpcinfo -p $TARGET_IP 2>/dev/null)

        if [ -z "$RPC_OUTPUT" ]; then
            echo "No RPC services detected on $TARGET_IP."
        exit 1
        fi
        ;;

        139|445)
        printf "\n\n${YELLOW}[+] SMB service is open and enumerating the shares...${NC}\n"   | tee -a "$LOG_FILE"
            nmap --script smb-enum-shares -p 139,445 $TARGET_IP  | tee -a "$LOG_FILE"
            printf "\n\n${YELLOW}[*] Looking for Eternal Blue vulnerability.........${NC}"   | tee -a "$LOG_FILE"
            nmap -p445 --script smb-vuln-ms17-010 $TARGET_IP  | tee -a  "$LOG_FILE" 
            if grep -q "CVE-2017-0143" "$LOG_FILE"; then
                printf "\n\n${RED}[+] Eternal Blue vulnerability is present${NC}\n" | tee -a "$LOG_FILE"
            else
                printf "\n\n${GREEN}[-] Eternal Blue vulnerability is not present${NC}\n" | tee -a "$LOG_FILE"
            fi
        enum4linux -U $TARGET_IP > temp.txt
            grep -Po '\[.*]' temp.txt | awk 'BEGIN{FS=" "} {print $1}' > temp2.txt
            if [ -s temp2.txt ]
            then
                printf "\n${YELLOW}The list of users found in this system...${NC}\n\n" | tee -a "$LOG_FILE"
                while read user; do
                   printf "\n${RED}${user}${NC}" | tee -a "$LOG_FILE"
                done <temp2.txt
            else
                printf "\n${GREEN}No users found in this system using SMB${NC}\n" | tee -a "$LOG_FILE"
            fi
            rm temp.txt temp2.txt
        printf "\n"
        ;;

        *)
            echo -e "${GREEN}No automation for port $port.${NC}"
            ;;

8000)
            # --- HTTP Scan (Port 8000) ---
            echo -e "\n${BLUE}[+] Scanning custom HTTP (Port 8000)...${NC}"
            URL="http://$TARGET_IP:8000/"
            # Gobuster scan
            gobuster dir -u $URL  \
            -w /usr/share/wordlists/dirb/common.txt \
             -t 50 -x php,html,txt -b 403,404 \
             -q --no-color > "$LOG_DIR/gobuster.log" 2>&1
             if [ -f "$FILTERS_DIR/filter_gobuster.sh" ]; then
                    "$FILTERS_DIR/filter_gobuster.sh" "$LOG_DIR/gobuster.log"
             fi
            
            ;;

    esac
done

# Restore Ctrl+C
stty intr ^C
echo -e "${GREEN}Scan completed. Logs saved in $LOG_DIR.${NC}"
