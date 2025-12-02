# benign_activity.py

import argparse
from entra_simulator import EntraLogSimulator
from datetime import datetime, timezone
import json

def main():
    parser = argparse.ArgumentParser(description="Generate benign Entra ID activity logs.")
    parser.add_argument(
        "--total-logs", type=int, default=50,
        help="Total number of benign logs to generate"
    )
    parser.add_argument(
        "--output", type=str,
        default="/home/spen/entra_logs/entra_logs.jsonl",
        help="Path to output .jsonl log file"
    )

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

    logs = simulator.generate_logs(
        total_logs=args.total_logs,
        simulate_start_time=datetime.now(timezone.utc),
        include_failures=True  # allows benign InteractiveUserSignIn failures
    )

    with open(args.output, "w") as out_file:
        for log in logs:
            out_file.write(f"{json.dumps(log)}\n")

    print(f"[+] Generated {len(logs)} benign logs to {args.output}")

if __name__ == "__main__":
    main()
