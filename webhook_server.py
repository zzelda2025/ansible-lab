from flask import Flask, request, jsonify
import subprocess
import requests
import json
import os
import hvac
import threading

app = Flask(__name__)

# -- Config ----------------------------------------------------
HCP_TOKEN   = os.environ.get("HCP_TOKEN")
HCP_ORG     = os.environ.get("HCP_ORG", "Devops-HTV")
VAULT_ADDR  = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
VAULT_TOKEN = os.environ.get("VAULT_TOKEN")
KNOWN_HOSTS = os.path.expanduser("~/.ssh/known_hosts")

WORKSPACE_CONFIG = {
    "proxmox-infra": {
        "output_key":  "database_vm_ip",
        "vault_path":  "ansible/proxmox",
        "playbook":    os.path.expanduser("~/ansible-lab/proxmox/site.yml"),
        "description": "Proxmox DB VM",
        "ssh_type":    "password",
    },
    "aws-infra": {
        "output_key":  "ec2_public_ip",
        "vault_path":  "ansible/aws",
        "playbook":    os.path.expanduser("~/ansible-lab/aws/site.yml"),
        "description": "AWS EC2 Web Server",
        "ssh_type":    "key",
    },
}


# -- Vault -----------------------------------------------------

def get_secrets_from_vault(vault_path):
    """Get secrets from HashiCorp Vault."""
    try:
        client = hvac.Client(url=VAULT_ADDR, token=VAULT_TOKEN)
        response = client.secrets.kv.v2.read_secret_version(
            path=vault_path,
            mount_point="secret",
            raise_on_deleted_version=True,
        )
        return response["data"]["data"]
    except Exception as e:
        print(f"[ERROR] Failed to get secrets from Vault path '{vault_path}': {e}")
        return None


# -- HCP Helpers -----------------------------------------------

def get_ip_from_hcp(workspace_name, output_key):
    """Get IP from HCP Terraform output by workspace."""
    if not HCP_TOKEN:
        print("[ERROR] HCP_TOKEN is not set!")
        return None

    headers = {
        "Authorization": f"Bearer {HCP_TOKEN}",
        "Content-Type": "application/vnd.api+json",
    }

    ws_url = f"https://app.terraform.io/api/v2/organizations/{HCP_ORG}/workspaces/{workspace_name}"
    try:
        resp = requests.get(ws_url, headers=headers, timeout=10)
    except requests.exceptions.Timeout:
        print(f"[ERROR] Timeout getting workspace '{workspace_name}'")
        return None

    if resp.status_code != 200:
        print(f"[ERROR] Failed to get workspace '{workspace_name}': {resp.status_code}")
        return None

    workspace_id = resp.json()["data"]["id"]

    out_url = f"https://app.terraform.io/api/v2/workspaces/{workspace_id}/current-state-version-outputs"
    try:
        resp2 = requests.get(out_url, headers=headers, timeout=10)
    except requests.exceptions.Timeout:
        print(f"[ERROR] Timeout getting outputs of workspace '{workspace_name}'")
        return None

    if resp2.status_code != 200:
        print(f"[ERROR] Failed to get outputs: {resp2.status_code}")
        return None

    for output in resp2.json().get("data", []):
        if output["attributes"]["name"] == output_key:
            raw_ip = output["attributes"]["value"]
            return raw_ip.split("/")[0]

    print(f"[WARN] Output '{output_key}' not found in workspace '{workspace_name}'.")
    return None


def get_aws_eip():
    """Get EIP of EC2 from aws-infra workspace."""
    return get_ip_from_hcp("aws-infra", "ec2_public_ip")


def is_destroy_run(run_id):
    """Check if run is a destroy run via HCP API."""
    if not run_id or not HCP_TOKEN:
        return False
    headers = {
        "Authorization": f"Bearer {HCP_TOKEN}",
        "Content-Type": "application/vnd.api+json",
    }
    try:
        resp = requests.get(
            f"https://app.terraform.io/api/v2/runs/{run_id}",
            headers=headers,
            timeout=10
        )
        if resp.status_code == 200:
            return resp.json()["data"]["attributes"].get("is-destroy", False)
    except requests.exceptions.Timeout:
        print(f"[ERROR] Timeout checking run '{run_id}'")
    return False


# -- Ansible ---------------------------------------------------

def run_ansible(vm_ip, playbook, vault_path, ssh_type="password", extra=None):
    """Run ansible-playbook with secrets from Vault."""
    subprocess.run(
        ["ssh-keygen", "-f", KNOWN_HOSTS, "-R", vm_ip],
        capture_output=True
    )

    # Get secrets from Vault
    secrets = get_secrets_from_vault(vault_path)
    if not secrets:
        return "", "Failed to get secrets from Vault", 1

    # Build extra vars: secrets + dynamic vars
    extra_vars = {
        "ansible_host": vm_ip,
        "ansible_ssh_extra_args": "-o StrictHostKeyChecking=no",
        **secrets,
    }

    # Add dynamic vars if any (e.g. wg_ec2_endpoint)
    if extra:
        for item in extra.split(" "):
            if "=" in item:
                k, v = item.split("=", 1)
                extra_vars[k] = v

    cmd = [
        "ansible-playbook",
        "-i", f"{vm_ip},",
        "--extra-vars", json.dumps(extra_vars, ensure_ascii=True),
        "--become",
        playbook,
    ]

    if ssh_type == "key":
        cmd.insert(1, "--private-key")
        cmd.insert(2, os.path.expanduser("~/.ssh/aws-key.pem"))

    print(f"[INFO] Running ansible-playbook for host: {vm_ip}")
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=os.path.dirname(playbook),
        env={**os.environ, "ANSIBLE_FORCE_COLOR": "0", "PYTHONIOENCODING": "utf-8"},
    )
    return result.stdout, result.stderr, result.returncode


def run_proxmox_with_eip():
    """
    Re-trigger Proxmox playbook with new EIP from AWS.
    Called after aws-infra apply completes.
    """
    print("[INFO] Auto-triggering Proxmox playbook to update WireGuard endpoint...")

    config     = WORKSPACE_CONFIG["proxmox-infra"]
    proxmox_ip = get_ip_from_hcp("proxmox-infra", config["output_key"])
    aws_eip    = get_aws_eip()

    if not proxmox_ip:
        print("[WARN] Auto-trigger: Failed to get Proxmox IP -- skipping.")
        return

    if not aws_eip:
        print("[WARN] Auto-trigger: Failed to get AWS EIP -- skipping.")
        return

    print(f"[INFO] Auto-trigger Proxmox: IP={proxmox_ip} | EIP={aws_eip}")
    stdout, stderr, rc = run_ansible(
        proxmox_ip,
        config["playbook"],
        config["vault_path"],
        config["ssh_type"],
        extra=f"wg_ec2_endpoint={aws_eip}",
    )

    print(f"[Auto-trigger STDOUT]\n{stdout}")
    if stderr:
        print(f"[Auto-trigger STDERR]\n{stderr}")

    if rc == 0:
        print("[INFO] Auto-trigger Proxmox playbook succeeded!")
    else:
        print(f"[ERROR] Auto-trigger Proxmox playbook failed (rc={rc})")


# -- Routes ----------------------------------------------------

@app.route("/webhook", methods=["POST"])
def webhook():
    data = request.json
    print(f"Received webhook: {json.dumps(data, indent=2)}")

    notifications = data.get("notifications", [])
    for notif in notifications:
        trigger = notif.get("trigger")

        if trigger == "verification":
            print("[INFO] Verification ping -- ignoring.")
            return jsonify({"status": "verified"}), 200

        if trigger == "run:completed":
            run_status     = notif.get("run_status")
            workspace_name = data.get("workspace_name")
            run_id         = data.get("run_id")
            print(f"[INFO] run:completed | workspace={workspace_name} | status={run_status}")

            if run_status != "applied":
                print(f"[INFO] Status is not 'applied' ({run_status}) -- ignoring.")
                return jsonify({"status": "ignored", "run_status": run_status}), 200

            if is_destroy_run(run_id):
                print("[INFO] This is a destroy run -- ignoring.")
                return jsonify({"status": "ignored", "reason": "destroy run"}), 200

            config = WORKSPACE_CONFIG.get(workspace_name)
            if not config:
                print(f"[WARN] Workspace '{workspace_name}' not in config -- ignoring.")
                return jsonify({"status": "ignored", "reason": "unknown workspace"}), 200

            print(f"[INFO] [{config['description']}] Apply succeeded! Getting IP from HCP...")
            vm_ip = get_ip_from_hcp(workspace_name, config["output_key"])

            if not vm_ip:
                return jsonify({"status": "error", "msg": "Failed to get IP from HCP"}), 500

            # Proxmox: get EIP if available, skip wireguard if not
            extra_vars = None
            if workspace_name == "proxmox-infra":
                aws_eip = get_aws_eip()
                if aws_eip:
                    print(f"[INFO] AWS EIP found: {aws_eip} -- will install WireGuard")
                    extra_vars = f"wg_ec2_endpoint={aws_eip}"
                else:
                    print("[INFO] AWS EIP not available -- installing PostgreSQL only, skipping WireGuard")

            print(f"[INFO] IP: {vm_ip} -- running Ansible [{config['description']}]...")
            stdout, stderr, rc = run_ansible(
                vm_ip,
                config["playbook"],
                config["vault_path"],
                config["ssh_type"],
                extra=extra_vars,
            )

            print(f"[Ansible STDOUT]\n{stdout}")
            if stderr:
                print(f"[Ansible STDERR]\n{stderr}")

            # AWS: after completion auto-trigger Proxmox to update WireGuard
            if workspace_name == "aws-infra" and rc == 0:
                print("[INFO] AWS apply done -- auto-triggering Proxmox in background...")
                t = threading.Thread(target=run_proxmox_with_eip, daemon=True)
                t.start()

            return jsonify({
                "status":     "success" if rc == 0 else "failed",
                "workspace":  workspace_name,
                "vm_ip":      vm_ip,
                "ansible_rc": rc,
            }), 200

    return jsonify({"status": "ignored"}), 200


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)