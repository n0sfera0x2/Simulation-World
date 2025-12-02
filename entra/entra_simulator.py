import json
import yaml
import uuid
import random
from datetime import datetime, timedelta, timezone
from typing import Dict, List


class EntraLogSimulator:
    def __init__(
        self,
        users_file="/home/spen/entra_logs/configs/users.yaml",
        service_principals_file="/home/spen/entra_logs/configs/service_principals.yaml",
        template_file="/home/spen/entra_logs/templates/entra_template.json",
        org_config_file="/home/spen/entra_logs/configs/org_config.yaml",
        apps_file="/home/spen/entra_logs/configs/apps.yaml",
        operations_file="/home/spen/entra_logs/configs/operations.yaml",
        output_file="/home/spen/entra_logs/entra_logs.jsonl"
    ):
        self.users_file = users_file
        self.service_principals_file = service_principals_file
        self.template_file = template_file
        self.org_config_file = org_config_file
        self.apps_file = apps_file
        self.operations_file = operations_file
        self.output_file = output_file

        self.users = self._load_yaml(self.users_file)["users"]
        self.service_principals = self._load_yaml(self.service_principals_file)["service_principals"]
        self.template = self._load_template()
        self.org_config = self._load_yaml(self.org_config_file)
        self.app_id_map = self._load_yaml(self.apps_file)["apps"]
        self.operations = self._load_yaml(self.operations_file)["operations"]

        self.operation_resource_map = {
            "InteractiveUserSignIn": "UserAccount",
            "TokenIssued": "UserAccount",
            "SendMail": "MailItem",
            "FileAccessed": "File",
            "AddMemberToGroup": "Group",
            "RemoveMemberFromGroup": "Group",
            "CreateTeam": "Team",
            "DeleteFile": "File",
            "DownloadFile": "File",
            "ViewSharePointPage": "Page",
            "UpdateCalendar": "CalendarEvent",
            "ShareFile": "File",
            "CreateChannel": "Channel",
            "JoinMeeting": "Meeting",
            "CreateUser": "UserAccount",
            "DeleteUser": "UserAccount",
            "ResetPassword": "UserAccount",
            "AddServicePrincipal": "ServicePrincipal",
            "SignInWithServicePrincipal": "ServicePrincipal",
            "ConsentToApp": "UserAccount"
        }

    def _load_yaml(self, filepath: str) -> Dict:
        with open(filepath, "r") as f:
            return yaml.safe_load(f)

    def _load_template(self) -> str:
        with open(self.template_file, "r") as f:
            return f.read()

    def _render_template(
        self,
        entity: Dict,
        operation: Dict,
        timestamp: str,
        is_failure: bool = False,
        is_spn: bool = False,
        override_app: Dict = None
    ) -> Dict:
        result_status = "Failure" if is_failure else self.org_config["result_status"]

        app_display = override_app["app_display_name"] if override_app else operation["app_display_name"]
        app_id = self.app_id_map.get(app_display, "00000000-0000-0000-0000-000000000000")
        resource_type = self.operation_resource_map.get(operation["name"], "Unknown")

        if is_spn:
            user_id = entity["spn_id"]
            user_type = "2"
            user_agent = "AzureAD-Application"
            device_id = "spn-device"
            os = "Unknown"
            browser = "Unknown"
            roles = ["ServicePrincipal"]
        else:
            user_id = entity["user_id"]
            roles = entity.get("roles", [])
            user_type = "10" if "guest" in roles else "0"
            user_agent = entity["user_agent"]
            device_id = entity["device_id"]
            os = entity["os"]
            browser = entity["browser"]

        replacements = {
            "{{ timestamp }}": timestamp,
            "{{ operation }}": operation["name"],
            "{{ org_id }}": self.org_config["org_id"],
            "{{ record_type }}": str(self.org_config["record_type"]),
            "{{ result_type }}": str(self.org_config["result_type"]),
            "{{ user_type }}": user_type,
            "{{ roles }}": json.dumps(roles),
            "{{ client_ip }}": entity["ip"],
            "{{ user_id }}": user_id,
            "{{ workload }}": "AzureActiveDirectory",
            "{{ result_status }}": result_status,
            "{{ device_id }}": device_id,
            "{{ os }}": os,
            "{{ browser }}": browser,
            "{{ user_agent }}": user_agent,
            "{{ app_id }}": self.app_id_map[app_display],
            "{{ app_display_name }}": app_display,
            "{{ event_id }}": str(uuid.uuid4()),
            "{{ auth_requirement }}": operation.get("auth_requirement", "None"),
            "{{ mfa_required }}": str(operation.get("mfa_required", False)).lower(),
            "{{ city }}": entity["city"],
            "{{ country }}": entity["country"],
            "{{ asn_number }}": entity["asn"],
            "{{ asn_name }}": entity["asn_name"],
            "{{ is_proxy }}": str(entity["is_proxy"]).lower(),
            "{{ resource }}": resource_type,
            "{{ email_sender }}": entity.get("email_sender", "attacker@evil.com"),
            "{{ email_subject }}": entity.get("email_subject", "Security Notice: Action Required"),
            "{{ email_url }}": entity.get("email_url", "https://login.microsoftonline.com-reset-verify.com")
        }
        

        filled = self.template
        for placeholder, value in replacements.items():
            filled = filled.replace(placeholder, str(value))

        return json.loads(filled)

    def generate_logs(
        self,
        total_logs: int = 50,
        simulate_start_time=None,
        include_failures=False,
        force_user: str = None,
        force_app: str = None,
        force_operation: str = None,
        is_attack: bool = False
    ) -> List[Dict]:
        if simulate_start_time is None:
            simulate_start_time = datetime.now(timezone.utc)

        logs = []
        current_time = simulate_start_time

        while len(logs) < total_logs:
            is_spn = random.random() < 0.2

            if force_user:
                entity = next((u for u in self.users if u["user_id"] == force_user), None)
                if not entity:
                    raise ValueError(f"User '{force_user}' not found.")
                is_spn = False
            elif is_spn:
                entity = random.choice(self.service_principals)
            else:
                entity = random.choice(self.users)

            if force_operation:
                operation = next((op for op in self.operations if op["name"] == force_operation), None)
                if not operation:
                    raise ValueError(f"Operation '{force_operation}' not found.")
            else:
                ops_pool = [
                    op for op in self.operations
                    if ("ServicePrincipal" in op["name"]) == is_spn
                ]
                if not ops_pool:
                    continue
                operation = random.choice(ops_pool)

            timestamp = current_time.strftime("%Y-%m-%dT%H:%M:%SZ")

            is_failure = (
                include_failures
                and operation["name"] == "InteractiveUserSignIn"
                and not is_spn
                and random.random() < 0.15
            )

            log = self._render_template(
                entity=entity,
                operation=operation,
                timestamp=timestamp,
                is_failure=is_failure,
                is_spn=is_spn,
                override_app={"app_display_name": force_app} if force_app else None
            )

            logs.append(log)
            current_time += timedelta(seconds=random.randint(15, 45))

        return logs
