from flask import Flask, request, jsonify
import subprocess
import requests
import json
import os

app = Flask(__name__)

# ── Config ────────────────────────────────────────────────────
HCP_TOKEN       = os.environ.get("HCP_TOKEN")
HCP_ORG         = os.environ.get("HCP_ORG", "Devops-HTV")
VAULT_PASS_FILE = os.path.expanduser("~/.vault_pass")
KNOWN_HOSTS     = os.path.expanduser("~/.ssh/known_hosts")

WORKSPACE_CONFIG = {
    "proxmox-infra": {
        "output_key":  "database_vm_ip",
        "secrets":     os.path.expanduser("~/ansible-lab/proxmox/secrets.yml"),
        "playbook":    os.path.expanduser("~/ansible-lab/proxmox/site.yml"),
        "description": "Proxmox DB VM",
        "ssh_type":    "password",
    },
    "aws-infra": {
        "output_key":  "ec2_public_ip",
        "secrets":     os.path.expanduser("~/ansible-lab/aws/secrets.yml"),
        "playbook":    os.path.expanduser("~/ansible-lab/aws/site.yml"),
        "description": "AWS EC2 Web Server",
        "ssh_type":    "key",
    },
}


# ── Helpers ───────────────────────────────────────────────────

def get_ip_from_hcp(workspace_name, output_key):
    """Lấy IP từ HCP Terraform output theo workspace."""
    if not HCP_TOKEN:
        print("[ERROR] HCP_TOKEN chưa được set!")
        return None

    headers = {
        "Authorization": f"Bearer {HCP_TOKEN}",
        "Content-Type": "application/vnd.api+json",
    }

    # Bước 1: lấy workspace ID
    ws_url = f"https://app.terraform.io/api/v2/organizations/{HCP_ORG}/workspaces/{workspace_name}"
    resp = requests.get(ws_url, headers=headers)
    if resp.status_code != 200:
        print(f"[ERROR] Không lấy được workspace '{workspace_name}': {resp.status_code}")
        return None

    workspace_id = resp.json()["data"]["id"]

    # Bước 2: lấy outputs
    out_url = f"https://app.terraform.io/api/v2/workspaces/{workspace_id}/current-state-version-outputs"
    resp2 = requests.get(out_url, headers=headers)
    if resp2.status_code != 200:
        print(f"[ERROR] Không lấy được outputs: {resp2.status_code}")
        return None

    for output in resp2.json().get("data", []):
        if output["attributes"]["name"] == output_key:
            raw_ip = output["attributes"]["value"]
            return raw_ip.split("/")[0]

    print(f"[WARN] Output '{output_key}' không tìm thấy trong workspace '{workspace_name}'.")
    return None


def get_aws_eip():
    """Lấy EIP của EC2 từ workspace aws-infra."""
    return get_ip_from_hcp("aws-infra", "ec2_public_ip")


def run_ansible(vm_ip, playbook, secrets, ssh_type="password", extra=None):
    """Chạy ansible-playbook với IP lấy từ HCP."""
    # Xoá host key cũ tránh lỗi host key changed
    subprocess.run(
        ["ssh-keygen", "-f", KNOWN_HOSTS, "-R", vm_ip],
        capture_output=True
    )

    # Base extra-vars
    base_extra = f"ansible_host={vm_ip} ansible_ssh_extra_args='-o StrictHostKeyChecking=no'"
    if extra:
        base_extra += f" {extra}"

    cmd = [
        "ansible-playbook",
        "-i", f"{vm_ip},",
        "--extra-vars", f"@{secrets}",          # secrets trước (priority thấp)
        "--vault-password-file", VAULT_PASS_FILE,
        "--extra-vars", base_extra,             # dynamic vars sau → ưu tiên cao nhất
        "--become",
        playbook,
    ]

    # AWS dùng key pair thay vì password
    if ssh_type == "key":
        cmd.insert(1, "--private-key")
        cmd.insert(2, os.path.expanduser("~/.ssh/aws-key.pem"))

    print(f"[INFO] Chạy ansible-playbook cho host: {vm_ip}")
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=os.path.dirname(playbook),
    )
    return result.stdout, result.stderr, result.returncode


# ── Routes ────────────────────────────────────────────────────

@app.route("/webhook", methods=["POST"])
def webhook():
    data = request.json
    print(f"Received webhook: {json.dumps(data, indent=2)}")

    notifications = data.get("notifications", [])
    for notif in notifications:
        trigger = notif.get("trigger")

        # Bỏ qua verification ping
        if trigger == "verification":
            print("[INFO] Verification ping — bỏ qua.")
            return jsonify({"status": "verified"}), 200

        if trigger == "run:completed":
            run_status     = notif.get("run_status")
            workspace_name = data.get("workspace_name")
            print(f"[INFO] run:completed | workspace={workspace_name} | status={run_status}")

            # Chỉ xử lý khi apply thành công
            if run_status != "applied":
                print(f"[INFO] Status không phải 'applied' ({run_status}) — bỏ qua.")
                return jsonify({"status": "ignored", "run_status": run_status}), 200

            config = WORKSPACE_CONFIG.get(workspace_name)
            if not config:
                print(f"[WARN] Workspace '{workspace_name}' không có trong cấu hình — bỏ qua.")
                return jsonify({"status": "ignored", "reason": "unknown workspace"}), 200

            print(f"[INFO] [{config['description']}] Apply thành công! Đang lấy IP từ HCP...")
            vm_ip = get_ip_from_hcp(workspace_name, config["output_key"])

            if not vm_ip:
                return jsonify({"status": "error", "msg": "Không lấy được IP từ HCP"}), 500

            # Với proxmox: tự động lấy EIP từ aws-infra
            extra_vars = None
            if workspace_name == "proxmox-infra":
                aws_eip = get_aws_eip()
                if aws_eip:
                    print(f"[INFO] Lấy được AWS EIP: {aws_eip} — truyền vào wg_ec2_endpoint")
                    extra_vars = f"wg_ec2_endpoint={aws_eip}"
                else:
                    print("[WARN] Không lấy được AWS EIP — dùng giá trị trong secrets.yml")

            print(f"[INFO] IP: {vm_ip} — đang chạy Ansible [{config['description']}]...")
            stdout, stderr, rc = run_ansible(
                vm_ip,
                config["playbook"],
                config["secrets"],
                config["ssh_type"],
                extra=extra_vars,
            )

            print(f"[Ansible STDOUT]\n{stdout}")
            if stderr:
                print(f"[Ansible STDERR]\n{stderr}")

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