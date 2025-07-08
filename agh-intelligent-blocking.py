#!/usr/bin/env python3
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

from file_read_backwards import FileReadBackwards

# --- CONFIGURATION ---
# AdGuard Home Details
AGH_HOST = "127.0.0.1"
AGH_USER = "admin"
AGH_PASS = "admin"
AGH_PORT = 3000

# Blocker Logic
IP_THRESHOLD = 5 # Minimum IP that accesses the same domain ...
TIME_WINDOW_SECONDS = 600 # within this specified time interval.
# How long to wait after a threat is detected to collect all offending IPs
COLLECTION_PERIOD_SECONDS = 5

# Paths and Files
LOG_FILE = "/opt/AdGuardHome/data/querylog.json"
DB_FILE = "/opt/adguardhome-blocker/tracker.db"

# Fail2ban Jail
FAIL2BAN_JAIL = "adguard-intelligent"
# --- END CONFIGURATION ---

# In-memory state to track domains that have triggered an alert
TRIGGERED_DOMAINS = {} # { "domain.com:TYPE": trigger_timestamp }

def setup_database():
    try:
        con = sqlite3.connect(DB_FILE)
        cur = con.cursor()
        cur.execute('''
            CREATE TABLE IF NOT EXISTS queries (
                id INTEGER PRIMARY KEY,
                timestamp TEXT NOT NULL,
                domain TEXT NOT NULL,
                query_type TEXT NOT NULL,
                client_ip TEXT NOT NULL,
                UNIQUE(domain, query_type, client_ip)
            )
        ''')
        con.commit()
        con.close()
        print("INFO: Database initialized successfully.")
    except sqlite3.Error as e:
        print(f"FATAL: Database setup failed: {e}")
        sys.exit(1)

def perform_blocks(domain, offending_ips):
    """Handles Custom Rules and Disallowed Clients via separate API endpoints."""
    print(f"ACTION: Starting block process for domain '{domain}' and {len(offending_ips)} IPs.")
    auth = f"{AGH_USER}:{AGH_PASS}"
    base_url = f"http://{AGH_HOST}:{AGH_PORT}/control"

    # --- Task 1: Update Custom Filtering Rules ---
    print("ACTION: Updating custom filtering rules...")
    try:
        # Step 1A: Get current custom rules from /filtering/status
        get_filter_result = subprocess.run(
            ["curl", "-s", "-u", auth, f"{base_url}/filtering/status"],
            check=True, capture_output=True, text=True
        )
        if not get_filter_result.stdout:
            print("ERROR: Received empty response when getting filtering status.")
        else:
            existing_rules = json.loads(get_filter_result.stdout).get("user_rules", [])
            rule_to_add = f"||{domain}^"

            if rule_to_add not in existing_rules:
                print(f"ACTION: Adding new rule for '{domain}'...")
                new_rules_list = existing_rules + [rule_to_add]
                data = json.dumps({"rules": new_rules_list})

                # Step 1B: Set the new list using /filtering/set_rules
                set_rules_result = subprocess.run(
                    ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                     "-u", auth, "-X", "POST", f"{base_url}/filtering/set_rules",
                     "-H", "Content-Type: application/json", "-d", data],
                    check=True, capture_output=True, text=True
                )
                status_code = set_rules_result.stdout.strip()
                if status_code == "200":
                    print(f"SUCCESS: Custom rules updated to block '{domain}'.")
                else:
                    print(f"ERROR: Failed to set custom rules. AGH responded with HTTP status {status_code}.")
            else:
                print(f"INFO: Rule for '{domain}' already exists in custom filters.")
    except Exception as e:
        print(f"ERROR: An exception occurred during custom rule update: {e}")

    # --- Task 2: Update Disallowed Clients ---
    print("ACTION: Updating disallowed clients list...")
    try:
        # Step 2A: Get current access lists from /access/list
        get_access_result = subprocess.run(
            ["curl", "-s", "-u", auth, f"{base_url}/access/list"],
            check=True, capture_output=True, text=True
        )
        if not get_access_result.stdout:
             print("ERROR: Received empty response when getting access lists.")
        else:
            access_lists = json.loads(get_access_result.stdout)
            disallowed_clients = set(access_lists.get("disallowed_clients", []))
            original_clients_count = len(disallowed_clients)

            # Add all new offending IPs to the set
            for ip in offending_ips:
                disallowed_clients.add(ip)

            # Step 2B: Set the new list using /access/set, only if it has changed
            if len(disallowed_clients) > original_clients_count:
                print(f"ACTION: Adding {len(disallowed_clients) - original_clients_count} new IPs to the disallowed list...")
                payload = {
                    "allowed_clients": access_lists.get("allowed_clients", []),
                    "disallowed_clients": list(disallowed_clients),
                    "blocked_hosts": access_lists.get("blocked_hosts", [])
                }
                data = json.dumps(payload)
                set_access_result = subprocess.run(
                    ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                     "-u", auth, "-X", "POST", f"{base_url}/access/set",
                     "-H", "Content-Type: application/json", "-d", data],
                    check=True, capture_output=True, text=True
                )
                status_code = set_access_result.stdout.strip()
                if status_code == "200":
                    print("SUCCESS: Disallowed clients list updated.")
                else:
                    print(f"ERROR: Failed to update disallowed clients list. AGH responded with HTTP status {status_code}.")
            else:
                print("INFO: All offending IPs were already in the disallowed list.")
    except Exception as e:
        print(f"ERROR: An exception occurred during disallowed client update: {e}")

    # --- Task 3: Ban IPs with Fail2ban ---
    print("ACTION: Checking IPs against Fail2ban jail...")
    try:
        status_output = subprocess.run(
            ["fail2ban-client", "status", FAIL2BAN_JAIL],
            check=True, capture_output=True, text=True
        ).stdout
        banned_ips_match = re.search(r"Banned IP list:\s+(.*)", status_output)
        currently_banned_ips = set(banned_ips_match.group(1).split()) if banned_ips_match else set()

        offending_ips_set = set(offending_ips)
        already_banned = offending_ips_set.intersection(currently_banned_ips)
        new_ips_to_ban = offending_ips_set.difference(currently_banned_ips)

        if already_banned:
            print(f"INFO: {len(already_banned)} offending IPs were already in the Fail2ban jail.")
        if new_ips_to_ban:
            print(f"ACTION: Banning {len(new_ips_to_ban)} new IPs: {list(new_ips_to_ban)}")
            for ip in new_ips_to_ban:
                try:
                    subprocess.run(
                        ["fail2ban-client", "set", FAIL2BAN_JAIL, "banip", ip],
                        check=True, capture_output=True, text=True
                    )
                    print(f"  - SUCCESS: Banned '{ip}'.")
                except subprocess.CalledProcessError as e:
                    print(f"  - ERROR: Failed to ban '{ip}': {e.stderr}")
        else:
            print("INFO: No new IPs to ban in Fail2ban.")
    except Exception as e:
        print(f"ERROR: An unexpected error occurred during Fail2ban action: {e}")

def process_log_entry(line, con):
    """Parses a log entry and adds it to the database."""
    try:
        data = json.loads(line)
        if data.get("CP", "") != "": return

        domain = data["QH"]
        query_type = data["QT"]
        client_ip = data["IP"]
        timestamp = data["T"]
        domain_key = f"{domain}:{query_type}"

        cur = con.cursor()
        cur.execute("INSERT OR IGNORE INTO queries (timestamp, domain, query_type, client_ip) VALUES (?, ?, ?, ?)",(timestamp, domain, query_type, client_ip))
        con.commit()

        # If a domain has not been triggered yet, check if it meets the threshold
        if domain_key not in TRIGGERED_DOMAINS:
            cur.execute("SELECT COUNT(client_ip) FROM queries WHERE domain = ? AND query_type = ?",(domain, query_type))
            count = cur.fetchone()[0]
            if count >= IP_THRESHOLD:
                print(f"ALERT: Threshold met for {domain_key}. Starting collection period...")
                TRIGGERED_DOMAINS[domain_key] = time.time()

    except (json.JSONDecodeError, KeyError): pass
    except sqlite3.Error as e: print(f"ERROR: SQLite operation failed: {e}")

def check_and_execute_blocks(con):
    """Checks for triggered domains whose collection period has ended."""
    now = time.time()
    # Iterate over a copy of the items, as we may modify the dictionary
    for domain_key, trigger_time in list(TRIGGERED_DOMAINS.items()):
        if now > trigger_time + COLLECTION_PERIOD_SECONDS:
            print(f"INFO: Collection period for {domain_key} has ended. Executing blocks.")
            domain, query_type = domain_key.split(":", 1)

            # Get ALL IPs for this attack from the database
            cur = con.cursor()
            cur.execute("SELECT client_ip FROM queries WHERE domain = ? AND query_type = ?", (domain, query_type))
            all_offending_ips = [row[0] for row in cur.fetchall()]

            if all_offending_ips:
                perform_blocks(domain, all_offending_ips)

            # Clean up records from the database and the trigger list
            cur.execute("DELETE FROM queries WHERE domain = ? AND query_type = ?", (domain, query_type))
            con.commit()
            del TRIGGERED_DOMAINS[domain_key]
            print(f"INFO: Cleared all records for '{domain_key}'.")

def main():
    """Main loop to tail logs and check for triggered blocks."""
    print("--- Intelligent Blocker Service Starting ---")
    setup_database()

    if not os.path.exists(LOG_FILE):
        print(f"FATAL: Log file not found at {LOG_FILE}. Exiting.")
        sys.exit(1)

    con = sqlite3.connect(DB_FILE)
    try:
        while True:
            # Cleanup old DB entries to keep it from growing indefinitely
            cutoff = datetime.now(timezone.utc) - timedelta(seconds=TIME_WINDOW_SECONDS)
            cur = con.cursor()
            cur.execute("DELETE FROM queries WHERE timestamp < ?", (cutoff.isoformat(),))
            con.commit()

            # Process new log entries
            with FileReadBackwards(LOG_FILE, encoding="utf-8") as frb:
                for line in frb:
                    process_log_entry(line, con)

            # Check if any collection periods have expired and execute blocks
            check_and_execute_blocks(con)

            time.sleep(5) # Wait before the next cycle
    except KeyboardInterrupt:
        print("\nINFO: Service shutting down.")
    finally:
        if con:
            con.close()
        print("--- Intelligent Blocker Service Stopped ---")

if __name__ == "__main__":
    main()
