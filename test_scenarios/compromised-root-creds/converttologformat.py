import yaml

input_yaml = "compromised-root-creds/attacker_s3_access_complete.yml"
output_log = "compromised-root-creds/attacker_s3_access_complete.log"

with open(input_yaml, "r") as f:
    data = yaml.safe_load(f)

logs = data.get("Logs", [])

with open(output_log, "w") as f:
    for line in logs:
        f.write(line + "\n")

print(f"✅ Wrote {len(logs)} log lines to {output_log}")