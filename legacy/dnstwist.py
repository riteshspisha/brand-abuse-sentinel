import json
import subprocess
import os
import datetime
# import boto3
import time

# ---------------- CONFIG ---------------- #
DOMAINS = ["ishafoundation.org", "isha.in", "sadhguru.org"]
S3_BUCKET_NAME = 'typosquatting-logs'
S3_PREFIX = 'dnstwist/raw_daily/'  # Prefix for raw consolidated logs
DNSTWIST_BIN = "/home/ssm-user/typosquatting_detection/dnstwist_env/bin/dnstwist"

# Local file to consolidate results
LOCAL_BATCH_FILE = "/tmp/dnstwist_daily_batch.jsonl"
# ----------------------------------------- #

# s3 = boto3.client('s3')

def run_dnstwist_batch():
    """Run DNSTwist for all domains and save to one local file."""
    if os.path.exists(LOCAL_BATCH_FILE):
        os.remove(LOCAL_BATCH_FILE)

    all_hits = 0
    print(f"[*] Starting Daily DNSTwist Batch for {len(DOMAINS)} domains...")

    with open(LOCAL_BATCH_FILE, 'a') as batch_file:
        for domain in DOMAINS:
            print(f"[+] Scanning: {domain}")
            try:
                # Use --format json for native parsing
                result = subprocess.run(
                    [DNSTWIST_BIN, "--registered", "--format", "json", domain],
                    capture_output=True, text=True, check=True
                )

                findings = json.loads(result.stdout)

                for item in findings:
                    # Filter out the original domain to save AI tokens
                    if item.get('fuzzer') == '*original':
                        continue

                    log_entry = {
                        "scan_timestamp": datetime.datetime.now().isoformat(),
                        "source_domain": domain,
                        "data": item
                    }
                    batch_file.write(json.dumps(log_entry) + "\n")
                    all_hits += 1

            except Exception as e:                                                                                                      print(f"[-] Error scanning {domain}: {e}")
    if all_hits > 0:
        pass
        # upload_and_cleanup()
    else:
        print("[!] No registered variations found today.")

def upload_and_cleanup():
    """Upload the single daily batch to S3."""
    now = datetime.datetime.now()
    # Organized by YYYY/MM/DD for easy S3 Lifecycle management
    s3_key = f"{S3_PREFIX}{now.strftime('%Y/%m/%d')}/dnstwist_batch_{now.strftime('%H%M%S')}.jsonl"
    try:
        s3.upload_file(LOCAL_BATCH_FILE, S3_BUCKET_NAME, s3_key)        
        print(f"[#] Success: Uploaded {s3_key}")
        os.remove(LOCAL_BATCH_FILE)
    except Exception as e:
        print(f"[-] S3 Upload Failed: {e}")

if __name__ == "__main__":
    run_dnstwist_batch()
