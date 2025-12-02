import argparse
import json
import uuid
from datetime import datetime, timezone

# --- EntraLogSimulator Placeholder (Assuming it handles the user lookup) ---
try:
    from entra_simulator import EntraLogSimulator
except ImportError:
    print("Warning: EntraLogSimulator class not found. Using a placeholder for initialization.")
    class EntraLogSimulator:
        def __init__(self, **kwargs):
            # Mock essential attributes needed for the script to run
            self.users = [{
                "user_id": "admin1@contoso.com",
                "ip": "44.192.30.81", 
                "display_name": "Admin One",
                # ... other user details
            }]

def generate_flat_oauth_consent_log(username, output_path, simulator):
    """
    Generates a high-fidelity, FLAT-SCHEMA Microsoft 365 Audit Log 
    for an OAuth consent event that matches the XDM rule expectations.
    """
    
    # 1. Find user context
    user = next((u for u in simulator.users if u.get("user_id") == username), None)
    if not user:
        user = {
            "user_id": username,
            "ip": "44.192.30.81", # Use the alert's IP
            "display_name": username.split('@')[0].capitalize(),
        }
        print(f"Warning: User '{username}' not found. Using default context.")

    # 2. Time logic
    consent_dt = datetime.now(timezone.utc)
    consent_ts = consent_dt.strftime("%Y-%m-%dT%H:%M:%SZ") # Simplified for the flat format

    # 3. Define the critical OAuth context (mimicking the original XSIAM alert's Raw Data)
    OAUTH_APP_ID = "10000000-dead-beef-baad-ph1shp0rtal" # Matches your sample log AppId
    OAUTH_APP_NAME = "Contoso Phish Portal"              # Matches your sample log AppDisplayName
    OAUTH_SCOPES = "Mail.ReadWrite, offline_access, MailboxSettings.ReadWrite"
    
    # The ConsentToApp log entry (FLAT STRUCTURE)
    log_entry = {
      "_time": consent_ts, 
      "Id": str(uuid.uuid4()),
      "Operation": "ConsentToApp",
      "OrganizationId": "67aaf9b4-57b8-4ca6-b68c-2274d63ff1b0",
      "RecordType": 15,
      "ResultType": 0,
      "UserType": 0,
      "Roles": ["employee"], 
      "ClientIP": user.get("ip"), # <-- FLAT FIELD
      "UserId": username,         # <-- FLAT FIELD
      "Workload": "AzureActiveDirectory",
      "ResultStatus": "Success",  # <-- FLAT FIELD
      "DeviceDetail": {           # <-- FLAT FIELD
        "DeviceId": "device-phish-consent",
        "OperatingSystem": "Windows 10",
        "Browser": "Chrome"
      }, 
      "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.88 Safari/537.36",
      "AppId": OAUTH_APP_ID,
      "AppDisplayName": OAUTH_APP_NAME,
      # Add necessary flat audit details
      "AdditionalDetails": [
        {"Key": "AuthenticationRequirement", "Value": "SingleFactorAuthentication"}, 
        {"Key": "MfaRequired", "Value": "false"},
        # IMPORTANT: Embed the malicious scopes/details here for the XSIAM correlation rule to find.
        {"Key": "RequestedScopes", "Value": OAUTH_SCOPES}, # Custom key for correlation
        {"Key": "ConsentType", "Value": "User"}
      ], 
      "GeoLocation": {"Country": "US", "City": "Dallas"}, # Must be present to map GeoLocation fields
      "ASN": {"ASN": "AS7018", "ASN_Name": "ATT-INTERNET4", "IsProxy": "false"},
      "Resource": "Application",
      # Add the full scope string here so the XSIAM correlation rule can easily grab it
      "ScopeDetails": OAUTH_SCOPES
    }
    
    # 4. Write log
    with open(output_path, "w") as f:
        f.write(json.dumps(log_entry) + "\n")

    print(f"[+] Malicious OAuth Consent log for {username} written to: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Inject a targeted OAuth consent simulation log (Flat Schema).")
    parser.add_argument("--username", 
                        default="admin1@contoso.com", 
                        help="User email to simulate attack for (defaults to admin1@contoso.com)")
    parser.add_argument("--output", 
                        default="/home/spen/threat_emulation/o365/mal_oauth_consent.jsonl", 
                        help="Output path for the logs")
    args = parser.parse_args()

    # Initialize the simulator instance (as before)
    simulator = EntraLogSimulator(
        users_file="/home/spen/entra_logs/configs/users.yaml",
        service_principals_file="/home/spen/entra_logs/configs/service_principals.yaml",
        template_file="/home/spen/entra_logs/templates/entra_template.json",
        org_config_file="/home/spen/entra_logs/configs/org_config.yaml",
        apps_file="/home/spen/entra_logs/configs/apps.yaml",
        operations_file="/home/spen/entra_logs/configs/operations.yaml",
        output_file=args.output
    )

    generate_flat_oauth_consent_log(args.username, args.output, simulator)

if __name__ == "__main__":
    main()
