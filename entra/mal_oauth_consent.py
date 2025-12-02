import argparse
import json
import uuid
from datetime import datetime, timezone

# --- EntraLogSimulator Placeholder (Needed for context setup) ---
try:
    from entra_simulator import EntraLogSimulator
except ImportError:
    print("Warning: EntraLogSimulator class not found. Using a placeholder for initialization.")
    class EntraLogSimulator:
        def __init__(self, **kwargs):
            # Mock essential attributes needed for the script to run
            # We'll assume a dummy user list for the lookup
            self.users = [{
                "user_id": "admin1@contoso.com",
                "ip": "44.192.30.81", 
                "display_name": "Admin One",
                # ... other user details
            }]

def generate_oauth_consent_log(username, output_path, simulator):
    """
    Generates a high-fidelity Microsoft Entra ID Audit Log for an OAuth consent event.
    """
    
    # 1. Define the specific Operation (bypassing operations.yaml)
    # Using the realistic activityDisplayName
    oauth_consent_operation = {
        "name": "ConsentToApp",
        "activityDisplayName": "Consent to application", # <-- REALISM FIX 1
        "category": "ApplicationManagement",
        "result_status": "Success",
        "loggedByService": "Core Directory",
        "custom_fields": {
            "targetResources": [
                {
                    "id": "f3b8a0c7-0d6d-4f0f-9a6c-2f1e3e8b9f77",
                    "displayName": "Contoso Phish Portal",
                    "type": "ServicePrincipal",
                    "userPrincipalName": "f3b8a0c7-0d6d-4f0f-9a6c-2f1e3e8b9f77@contoso.onmicrosoft.com"
                }
            ],
            "additionalDetails": [
                {"key": "ConsentType", "value": "User"},
                {"key": "RequestedPermissions", "value": "Mail.ReadWrite, offline_access, MailboxSettings.ReadWrite"},
                {"key": "ClientAppId", "value": "f3b8a0c7-0d6d-4f0f-9a6c-2f1e3e8b9f77"}
            ]
        }
    }
    
    # 2. Find matching user from simulator's user list (required for context)
    user = next((u for u in simulator.users if u.get("user_id") == username), None)
    if not user:
        # Fallback/Default data if user isn't found in simulator context
        user = {
            "user_id": username,
            "ip": "44.192.30.81", # Default IP from the alert object
            "display_name": username.split('@')[0].capitalize(),
        }
        print(f"Warning: User '{username}' not found in users.yaml. Using default context data.")


    # 3. Time logic: Using microseconds for higher realism
    # Real Entra ID logs often use high-precision timestamps
    consent_dt = datetime.now(timezone.utc)
    # Format: YYYY-MM-DDTHH:MM:SS.mmmZ
    consent_ts = consent_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z" 
    
    # 4. Manually construct the final log object
    log_entry = {
      "time": consent_ts, # <-- REALISM FIX 2: High precision timestamp
      "id": str(uuid.uuid4()),
      "operationName": oauth_consent_operation["name"],
      "category": oauth_consent_operation["category"],
      "result": oauth_consent_operation["result_status"],
      "activityDisplayName": oauth_consent_operation["activityDisplayName"],
      "loggedByService": oauth_consent_operation["loggedByService"],
      "initiatedBy": {
        "user": {
          "id": f"user-{hash(username)}", 
          "displayName": user.get("display_name"), # <-- REALISM FIX 3: Added displayName
          "userPrincipalName": username,
          "ipAddress": user.get("ip")
        },
        "type": "User" # <-- REALISM FIX 4: Added initiator type
      },
      "targetResources": oauth_consent_operation["custom_fields"]["targetResources"],
      "additionalDetails": oauth_consent_operation["custom_fields"]["additionalDetails"],
      # <-- REALISM FIX 5 & 6: Added Client Context
      "clientAppId": "00000003-0000-0ff1-ce00-000000000000", # Common ID for Exchange/M365 client
      "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.88 Safari/537.36" 
    }
    
    # 5. Write log
    with open(output_path, "w") as f:
        f.write(json.dumps(log_entry) + "\n")

    print(f"[+] High-fidelity OAuth Consent log for {username} written to: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Inject a targeted OAuth consent simulation log.")
    parser.add_argument("--username", 
                        default="admin1@contoso.com", 
                        help="User email to simulate attack for (defaults to admin1@contoso.com)")
    parser.add_argument("--output", 
                        default="/home/spen/threat_emulation/o365/oauth_consent.jsonl", 
                        help="Output path for the logs")
    args = parser.parse_args()

    # Initialize the simulator instance to read existing configurations
    # This step is critical for pulling the real user context from your YAML files
    simulator = EntraLogSimulator(
        users_file="/home/spen/entra_logs/configs/users.yaml",
        service_principals_file="/home/spen/entra_logs/configs/service_principals.yaml",
        template_file="/home/spen/entra_logs/templates/entra_template.json",
        org_config_file="/home/spen/entra_logs/configs/org_config.yaml",
        apps_file="/home/spen/entra_logs/configs/apps.yaml",
        operations_file="/home/spen/entra_logs/configs/operations.yaml",
        output_file=args.output
    )

    generate_oauth_consent_log(args.username, args.output, simulator)

if __name__ == "__main__":
    main()
