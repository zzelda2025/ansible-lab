#!/usr/bin/env python3
import requests
import json
import os

HCP_TOKEN = os.environ.get("HCP_TOKEN")
HCP_ORG   = os.environ.get("HCP_ORG", "Devops-HTV")

def get_ip_from_hcp(workspace_name, output_key):
    headers = {
        "Authorization": f"Bearer {HCP_TOKEN}",
        "Content-Type": "application/vnd.api+json",
    }
    ws_url = f"https://app.terraform.io/api/v2/organizations/{HCP_ORG}/workspaces/{workspace_name}"
    resp = requests.get(ws_url, headers=headers, timeout=10)
    if resp.status_code != 200:
        return None
    workspace_id = resp.json()["data"]["id"]

    out_url = f"https://app.terraform.io/api/v2/workspaces/{workspace_id}/current-state-version-outputs"
    resp2 = requests.get(out_url, headers=headers, timeout=10)
    if resp2.status_code != 200:
        return None

    for output in resp2.json().get("data", []):
        if output["attributes"]["name"] == output_key:
            return output["attributes"]["value"].split("/")[0]
    return None

proxmox_ip = get_ip_from_hcp("proxmox-infra", "database_vm_ip")
aws_eip    = get_ip_from_hcp("aws-infra",     "ec2_public_ip")

inventory = {
    "dbservers": {
        "hosts": [proxmox_ip]
    },
    "_meta": {
        "hostvars": {
            proxmox_ip: {
                "ansible_user":        "vinh",
                "wg_ec2_endpoint":     aws_eip,
            }
        }
    }
}

print(json.dumps(inventory))
