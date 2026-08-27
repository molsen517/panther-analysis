#!/usr/bin/env python3
"""
Master script to run all compromised root credentials test scenarios in sequence.
This script executes all the individual scenario scripts in the correct order.
"""

import subprocess
import sys
import time
from datetime import datetime, timezone

# List of scripts to run in order
SCRIPTS = [
    "01_send_victim_okta.py",
    "02_send_victim_cloudtrail.py", 
    "03_send_attacker_okta.py",
    "04_send_attacker_cloudtrail.py",
    "05_send_attacker_s3_access.py",
    "06_send_attacker_vpc.py",
    "07_send_session_takeover_okta.py",
    "08_send_access_key_compromise.py"
]

def run_script(script_name):
    """Run a single script and return success status."""
    print(f"\n{'='*60}")
    print(f"Running {script_name}")
    print(f"{'='*60}")
    
    try:
        result = subprocess.run([sys.executable, script_name], check=True, text=True)
        print(f"✅ {script_name} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {script_name} failed with exit code {e.returncode}")
        return False
    except FileNotFoundError:
        print(f"❌ {script_name} not found")
        return False

def main():
    """Run all test scenario scripts in sequence, or just one."""
    print("🚀 Starting Compromised Root Credentials Test Scenario")
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("\nThis will run the following scenarios in order:")
    for i, script in enumerate(SCRIPTS, 1):
        print(f"  {i}. {script}")

    print(f"\n⚠️  Make sure you have updated config.py with your AWS account details!")
    print("   - AWS_ACCOUNT_ID")
    print("   - PANTHER_BUCKET_NAME")
    print("   - AWS_REGION (if different)")

    # Prompt user to run all or select one
    print("\nWould you like to run all scenarios or just one?")
    print("  1. Run all scenarios")
    print("  2. Run a single scenario")
    choice = input("Enter 1 or 2 (default 1): ").strip()
    if choice == "2":
        print("\nSelect a scenario to run:")
        for i, script in enumerate(SCRIPTS, 1):
            print(f"  {i}. {script}")
        selection = input("Enter the scenario number: ").strip()
        try:
            idx = int(selection) - 1
            if idx < 0 or idx >= len(SCRIPTS):
                print("Invalid selection. Aborting.")
                sys.exit(1)
            selected_scripts = [SCRIPTS[idx]]
        except ValueError:
            print("Invalid input. Aborting.")
            sys.exit(1)
    else:
        selected_scripts = SCRIPTS

    # Ask for confirmation
    #response = input("\nProceed with running the selected scenario(s)? (y/N): ").strip().lower()
    #if response not in ['y', 'yes']:
    #    print("Aborted by user.")
    #    sys.exit(0)

    # Track results
    successful = 0
    failed = 0

    # Run each script
    for script in selected_scripts:
        if run_script(script):
            successful += 1
        else:
            failed += 1
            print(f"\n⚠️  Script {script} failed. Continue with remaining scripts? (y/N): ", end="")
            response = input().strip().lower()
            if response not in ['y', 'yes']:
                print("Stopping execution due to user request.")
                break

        # Small delay between scripts
        time.sleep(2)

    # Summary
    print(f"\n{'='*60}")
    print("EXECUTION SUMMARY")
    print(f"{'='*60}")
    print(f"✅ Successful: {successful}")
    print(f"❌ Failed: {failed}")
    print(f"📊 Total: {successful + failed}")

    if failed == 0:
        print("\n🎉 All scenarios completed successfully!")
        print("Check your Panther console for the ingested logs.")
    else:
        print(f"\n⚠️  {failed} scenario(s) failed. Check the output above for details.")
        sys.exit(1)

if __name__ == "__main__":
    main()