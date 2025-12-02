import argparse
from datetime import datetime, timedelta, timezone
from entra_simulator import EntraLogSimulator
import json

def main():
    parser = argparse.ArgumentParser(description="Inject phishing root cause logs.")
    parser.add_argument("--username", required=True, help="User email to simulate attack for (must match users.yaml)")
    parser.add_argument("--output", required=True, help="Output .jsonl file path")
    parser.add_argument("--offset-minutes", type=int, default=60, help="Minutes before now to inject log")

    args = parser.parse_args()
    simulate_time = datetime.now(timezone.utc) - timedelta(minutes=args.offset_minutes)

    simulator = EntraLogSimulator(
        users_file="/home/spen/entra_logs/configs/users.yaml",
        service_principals_file="/home/spen/entra_logs/configs/service_principals.yaml",
        template_file="/home/spen/entra_logs/templates/entra_template.json",
        org_config_file="/home/spen/entra_logs/configs/org_config.yaml",
        apps_file="/home/spen/entra_logs/configs/apps.yaml",
        operations_file="/home/spen/entra_logs/configs/operations.yaml",
        output_file=args.output
    )

    logs = simulator.generate_logs(
        total_logs=1,
        simulate_start_time=simulate_time,
        force_user=args.username,
        force_app="Contoso Phish Portal",
        force_operation="ConsentToApp",
        is_attack=True
    )

    with open(args.output, "w") as f:
        for log in logs:
            f.write(f"{json.dumps(log)}\n")

    print(f"[+] Injected phishing root cause at {simulate_time.isoformat()} for {args.username} into {args.output}")

if __name__ == "__main__":
    main()
