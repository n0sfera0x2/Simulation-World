import argparse
import json
from datetime import datetime, timedelta, timezone
from entra_simulator import EntraLogSimulator

def generate_token_theft_logs(simulator, username, output_path):
    # Find matching user from users.yaml
    user = next((u for u in simulator.users if u["user_id"] == username), None)
    if not user:
        raise ValueError(f"User '{username}' not found in users.yaml")

    # Time logic: token first, then sign-in 3 minutes later
    now = datetime.now(timezone.utc)
    token_ts = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    signin_ts = (now + timedelta(minutes=3)).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Operation templates
    token_op = next(op for op in simulator.operations if op["name"] == "TokenIssued")
    signin_op = next(op for op in simulator.operations if op["name"] == "InteractiveUserSignIn")

    # Step 1: Legitimate token issuance
    token_log = simulator._render_template(
        entity=user,
        operation=token_op,
        timestamp=token_ts,
        is_failure=False,
        is_spn=False
    )

    # Step 2: Malicious follow-up login (different IP & OS)
    attacker = user.copy()
    attacker.update({
        "ip": "203.0.113.99",  # Anomalous IP
        "os": "Kali Linux",    # Anomalous OS
        "browser": "Unknown",
        "device_id": "device-attacker",
        "user_agent": "curl/8.1.0",
        "city": "Moscow",
        "country": "RU",
        "asn": "AS12389",
        "asn_name": "Rostelecom",
        "is_proxy": True
    })

    signin_log = simulator._render_template(
        entity=attacker,
        operation=signin_op,
        timestamp=signin_ts,
        is_failure=False,
        is_spn=False
    )

    # Write logs
    with open(output_path, "w") as f:
        f.write(json.dumps(token_log) + "\n")
        f.write(json.dumps(signin_log) + "\n")

    print(f"[+] Token theft simulation for {username} written to: {output_path}")

def main():
    parser = argparse.ArgumentParser(description="Inject token theft simulation logs.")
    parser.add_argument("--username", required=True, help="User email to simulate attack for (must match users.yaml)")
    parser.add_argument("--output", default="/home/spen/threat_emulation/o365/token_theft.jsonl", help="Output path for the logs")
    args = parser.parse_args()

    simulator = EntraLogSimulator(
        users_file="/home/spen/entra_logs/configs/users.yaml",
        service_principals_file="/home/spen/entra_logs/configs/service_principals.yaml",
        template_file="/home/spen/entra_logs/templates/entra_template.json",
        org_config_file="/home/spen/entra_logs/configs/org_config.yaml",
        apps_file="/home/spen/entra_logs/configs/apps.yaml",
        operations_file="/home/spen/entra_logs/configs/operations.yaml",
        output_file=args.output
    )

    generate_token_theft_logs(simulator, args.username, args.output)

if __name__ == "__main__":
    main()
