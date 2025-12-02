import argparse
import json
import uuid
from datetime import datetime, timezone

# Assuming EntraLogSimulator is accessible (either imported from a module or defined locally)
# For this example, we'll assume the essential method is available.
# NOTE: You will need to ensure EntraLogSimulator is configured in your actual environment.
# Since you provided the main function of your original script, I'll use a placeholder for the class.
try:
    from entra_simulator import EntraLogSimulator
except ImportError:
    print("Warning: EntraLogSimulator class not found. Using a placeholder.")
    class EntraLogSimulator:
        def __init__(self, **kwargs):
            # Mock essential attributes needed for the script to run
            self.users = []
        def _render_template(self, entity, operation, timestamp, is_failure, is_spn):
            # This would be the actual log rendering logic from your framework
            # For a standalone script, we will define the structure manually below.
            raise NotImplementedError("Placeholder simulator cannot render templates.")


def generate_oauth_consent_log(username, output_path, simulator):
    """
    Generates a single raw Microsoft Entra ID Audit Log for an OAuth consent event.
    """
    # 1. Define the specific Operation (bypassing operations.yaml)
    oauth_consent_operation = {
        "name": "ConsentToApp",
        "auth_requirement": "SingleFactorAuthentication",
        "mfa_required": False,
        "app_display_name": "Contoso Phish Portal",
        "result_status": "Success",
        "category": "ApplicationManagement",
        "risk_level": "High",
        "description": "User granted consent to third-party application",
        "audit_only": False,
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
            "ip": "44.192.30.81", # Corresponds to the srcIp in your alert object
            "os": "Windows 10",
            "browser": "Chrome",
            "city": "Dallas",
            "country": "US",
            "asn": "AS0000",
            "asn_name": "GenericISP",
            "is_proxy": False,
            "display_name": username.split('@')[0].capitalize()
        }
        print(f"Warning: User '{username}' not found in users.yaml. Using default context data.")


    # 3. Time logic
    consent_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    # 4. Manually construct the final log object using the defined structure
    # NOTE: If simulator._render_template can handle the 'operation' object, use that.
    # Otherwise, use the structure below:
    
    log_entry = {
      "time": consent_ts,
      "id": str(uuid.uuid4()),
      "operationName": oauth_consent_operation["name"],
      "category": oauth_consent_operation["category"],
      "result": oauth_consent_operation["result_status"],
      "activityDisplayName": oauth_consent_operation["description"],
      "loggedByService": "Core Directory",
      "initiatedBy": {
        "user": {
          "id": f"user-{hash(username)}", # Simulated User ID
          "displayName": user.get("display_name"),
          "userPrincipalName": username,
          "ipAddress": user.get("ip")
        }
      },
      "targetResources": oauth_consent_operation["custom_fields"]["targetResources"],
      "additionalDetails": oauth_consent_operation["custom_fields"]["additionalDetails"]
    }
    
    # 5. Write log
    with open(output_path, "w") as f:
        f.write(json.dumps(log_entry) + "\n")

    print(f"[+] OAuth Consent log for {username} written to: {output_path}")


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
