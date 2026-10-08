import json
import re
import os
import boto3
import certstream
import time
import Levenshtein
from datetime import datetime, timedelta, timezone

# -------- CONFIG -------- #
LOCAL_WS_URL = 'ws://localhost:8080/full-stream'
S3_BUCKET_NAME = os.environ.get('S3_BUCKET_NAME', 'typosquatting-logs')
AWS_REGION = os.environ.get('AWS_REGION', 'ap-south-1')

PENDING_ALERTS_FILE = 'pending_alerts.jsonl'
UPLOAD_INTERVAL = 3600

# DEDUPLICATION CONFIG
# Prevents the same domain from alerting twice within the same upload cycle
seen_domains = set()

STRICT_KEYWORDS = ["isha"]
STRICT_PATTERNS = [re.compile(rf"(^|[\.-]){re.escape(k)}([\.-]|$)", re.I) for k in STRICT_KEYWORDS]

BRAND_KEYWORDS = ["sadhguru", "innerengineering", "savesoil", "adiyogi", "consciousplanet",
                  "ishafoundation", "shambhavi", "dhyanalinga", "lingabhairavi", "cauverycalling"]
BRAND_PATTERN = re.compile(rf"({'|'.join(BRAND_KEYWORDS)})", re.I)

TARGET_BRANDS = ["sadhguru", "innerengineering", "savesoil", "ishafoundation"]

EXCLUSIONS = ["odisha", "vaishali", "shisha", "mishan", "vishal", "ehtisham", "abhishek", "rishana"]
WHITELIST = ["isha.in","sadhguru.org", "innerengineering.com", "consciousplanet.org", "ishalife.com", "ishaoutreach.org"]
# ------------------------ #

s3_client = boto3.client('s3', region_name=AWS_REGION)
last_upload_time = time.time()

def get_ist_now():
    return datetime.now(timezone.utc) + timedelta(hours=5, minutes=30)

def is_typo_match(domain_part):
    for brand in TARGET_BRANDS:
        distance = Levenshtein.distance(domain_part.lower(), brand)
        if 0 < distance <= 2:
            return True, brand
    return False, None

def upload_batch_to_s3():
    global last_upload_time, seen_domains
    if not os.path.exists(PENDING_ALERTS_FILE) or os.path.getsize(PENDING_ALERTS_FILE) == 0:
        last_upload_time = time.time()
        return

    ist_now = get_ist_now()
    s3_key = (f"certstream/raw_daily/{ist_now.strftime('%Y/%m/%d')}/"
              f"batch_{ist_now.strftime('%H%M%S')}.jsonl")

    try:
        upload_temp_name = f"uploading_{int(time.time())}.jsonl"
        os.rename(PENDING_ALERTS_FILE, upload_temp_name)

        s3_client.upload_file(upload_temp_name, S3_BUCKET_NAME, s3_key)
        print(f"[#] IST {ist_now.strftime('%H:%M:%S')} | Uploaded Batch to S3: {s3_key}")

        os.remove(upload_temp_name)

        # --- DEDUPLICATION RESET ---
        # Clear the cache after upload so we don't consume infinite memory
        # This means a domain can reappear once per hour (per S3 file)
        seen_domains.clear()

        last_upload_time = time.time()
    except Exception as e:
        print(f"[-] S3 Batch Upload Error: {e}")

def certstream_callback(message, context):
    global last_upload_time, seen_domains

    if time.time() - last_upload_time > UPLOAD_INTERVAL:
        upload_batch_to_s3()

    if message.get("message_type") == "certificate_update":
        leaf = message.get("data", {}).get("leaf_cert", {})
        all_domains = leaf.get("all_domains", [])

        for d in all_domains:
            d_lower = d.lower()

            # --- DEDUPLICATION CHECK ---
            if d_lower in seen_domains:
                continue

            # --- FILTERING ---
            if any(w in d_lower for w in WHITELIST): continue
            if any(ex in d_lower for ex in EXCLUSIONS): continue

            # --- MATCHING ---
            strict_matches = [k for i, k in enumerate(STRICT_KEYWORDS) if STRICT_PATTERNS[i].search(d)]
            brand_matches = BRAND_PATTERN.findall(d_lower)

            domain_parts = d_lower.replace('-', '.').split('.')
            typo_found, typo_target = False, ""
            for part in domain_parts:
                is_typo, brand_name = is_typo_match(part)
                if is_typo:
                    typo_found, typo_target = True, brand_name
                    break

            # --- LOGGING ---
            if strict_matches or brand_matches or typo_found:
                reasons = []
                if strict_matches: reasons.append(f"Strict Keyword: {strict_matches}")
                if brand_matches: reasons.append(f"Brand: {brand_matches}")
                if typo_found: reasons.append(f"Typo Similarity: {typo_target}")

                # Add to deduplication set
                seen_domains.add(d_lower)

                print(f"[!] Alert: {d} | {reasons}")

                log_entry = {
                    "timestamp_ist": get_ist_now().strftime('%Y-%m-%d %H:%M:%S'),
                    "domain": d,
                    "issuer": leaf.get("issuer", {}).get("O", "Unknown"),
                    "reasons": reasons,
                    "is_fuzzy_typo": typo_found
                }

                with open(PENDING_ALERTS_FILE, 'a') as f:
                    f.write(json.dumps(log_entry) + '\n')

                break

if __name__ == "__main__":
    print(f"[*] Starting Production Monitor (IST Mode)...")
    print(f"[*] Batch Upload Interval: {UPLOAD_INTERVAL}s")

    while True:
        try:
            certstream.listen_for_events(certstream_callback, url=LOCAL_WS_URL)
        except Exception as e:
            print(f"[-] Connection lost: {e}. Retrying in 5s...")
            time.sleep(5)