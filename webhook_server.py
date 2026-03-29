from flask import Flask, request, jsonify, render_template_string, redirect, session, Response
import subprocess
import requests
import json
import os
import hvac
import threading
import uuid
import time
import socket
import sqlite3
from datetime import datetime, timezone
from functools import wraps

app = Flask(__name__)
app.secret_key = os.urandom(24)

# ── Config ────────────────────────────────────────────────────
HCP_TOKEN        = os.environ.get("HCP_TOKEN")
HCP_ORG          = os.environ.get("HCP_ORG", "Devops-HTV")
VAULT_ADDR       = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
VAULT_TOKEN      = os.environ.get("VAULT_TOKEN")
KNOWN_HOSTS      = os.path.expanduser("~/.ssh/known_hosts")
WEBHOOK_BASE_URL = os.environ.get("WEBHOOK_BASE_URL", "http://localhost:5000")
DB_PATH          = os.path.expanduser("~/ansible-lab/jobs.db")

UI_USERNAME      = "vinh.thai"
UI_PASSWORD      = "VFS@2025"

TELEGRAM_TOKEN   = "8464142683:AAGl4jHWzFv-T4e15iPvnrVHOODEEvZ8Y64"
TELEGRAM_CHAT_ID = "-5080541786"

APPROVAL_TIMEOUT = 30 * 60  # 30 minutes
SSH_WAIT_TIMEOUT = 5  * 60  # 5 minutes

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

# In-memory stream buffers: job_id -> list of log lines
stream_buffers = {}
stream_locks   = {}
auto_reject_timers = {}


# ── SQLite ────────────────────────────────────────────────────

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS jobs (
            id           TEXT PRIMARY KEY,
            workspace    TEXT,
            description  TEXT,
            vm_ip        TEXT,
            playbook     TEXT,
            vault_path   TEXT,
            ssh_type     TEXT,
            extra        TEXT,
            dry_run_out  TEXT,
            result       TEXT,
            status       TEXT,
            created_at   TEXT,
            updated_at   TEXT
        )
    """)
    conn.commit()
    conn.close()


def db_save_job(job):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT OR REPLACE INTO jobs
        (id, workspace, description, vm_ip, playbook, vault_path, ssh_type,
         extra, dry_run_out, result, status, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        job["id"], job["workspace"], job["description"], job["vm_ip"],
        job["playbook"], job["vault_path"], job["ssh_type"], job.get("extra"),
        job.get("dry_run_out"), job.get("result"), job["status"],
        job["created_at"], now_str()
    ))
    conn.commit()
    conn.close()


def db_update_job(job_id, **kwargs):
    kwargs["updated_at"] = now_str()
    sets  = ", ".join(f"{k} = ?" for k in kwargs)
    vals  = list(kwargs.values()) + [job_id]
    conn  = sqlite3.connect(DB_PATH)
    conn.execute(f"UPDATE jobs SET {sets} WHERE id = ?", vals)
    conn.commit()
    conn.close()


def db_get_job(job_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def db_list_jobs(limit=50):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def now_str():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# ── Telegram ──────────────────────────────────────────────────

def send_telegram(message):
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        requests.post(url, json={
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "HTML"
        }, timeout=10)
    except Exception as e:
        print(f"[ERROR] Telegram send failed: {e}")


# ── Vault ─────────────────────────────────────────────────────

def get_secrets_from_vault(vault_path):
    try:
        client = hvac.Client(url=VAULT_ADDR, token=VAULT_TOKEN)
        response = client.secrets.kv.v2.read_secret_version(
            path=vault_path,
            mount_point="secret",
            raise_on_deleted_version=True,
        )
        return response["data"]["data"]
    except Exception as e:
        print(f"[ERROR] Failed to get secrets from Vault '{vault_path}': {e}")
        return None


# ── HCP Helpers ───────────────────────────────────────────────

def get_ip_from_hcp(workspace_name, output_key):
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
        return None
    if resp.status_code != 200:
        return None
    workspace_id = resp.json()["data"]["id"]
    out_url = f"https://app.terraform.io/api/v2/workspaces/{workspace_id}/current-state-version-outputs"
    try:
        resp2 = requests.get(out_url, headers=headers, timeout=10)
    except requests.exceptions.Timeout:
        return None
    if resp2.status_code != 200:
        return None
    for output in resp2.json().get("data", []):
        if output["attributes"]["name"] == output_key:
            return output["attributes"]["value"].split("/")[0]
    return None


def get_aws_eip():
    return get_ip_from_hcp("aws-infra", "ec2_public_ip")


def is_destroy_run(run_id):
    if not run_id or not HCP_TOKEN:
        return False
    headers = {
        "Authorization": f"Bearer {HCP_TOKEN}",
        "Content-Type": "application/vnd.api+json",
    }
    try:
        resp = requests.get(
            f"https://app.terraform.io/api/v2/runs/{run_id}",
            headers=headers, timeout=10
        )
        if resp.status_code == 200:
            return resp.json()["data"]["attributes"].get("is-destroy", False)
    except Exception:
        pass
    return False


# ── SSH Wait ──────────────────────────────────────────────────

def wait_for_ssh(host, port=22, timeout=SSH_WAIT_TIMEOUT):
    """Cho SSH san sang truoc khi chay Ansible."""
    print(f"[INFO] Waiting for SSH on {host}:{port} (timeout {timeout}s)...")
    start = time.time()
    while time.time() - start < timeout:
        try:
            sock = socket.create_connection((host, port), timeout=5)
            sock.close()
            print(f"[INFO] SSH is ready on {host}.")
            return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            time.sleep(10)
    print(f"[WARN] SSH not available on {host} after {timeout}s.")
    return False


# ── Ansible ───────────────────────────────────────────────────

def build_cmd(vm_ip, playbook, secrets, ssh_type, extra=None, check=False):
    extra_vars = {
        "ansible_host": vm_ip,
        "ansible_ssh_extra_args": "-o StrictHostKeyChecking=no",
        **secrets,
    }
    if extra:
        for item in extra.split(" "):
            if "=" in item:
                k, v = item.split("=", 1)
                extra_vars[k] = v

    cmd = ["ansible-playbook"]
    if check:
        cmd += ["--check", "--diff"]
    cmd += [
        "-i", f"{vm_ip},",
        "--extra-vars", json.dumps(extra_vars, ensure_ascii=True),
        "--become",
        playbook,
    ]
    if ssh_type == "key":
        cmd.insert(1, "--private-key")
        cmd.insert(2, os.path.expanduser("~/.ssh/aws-key.pem"))
    return cmd


def run_ansible_check(vm_ip, playbook, vault_path, ssh_type, extra=None):
    """Dry run - kiem tra nhung gi se thay doi."""
    subprocess.run(["ssh-keygen", "-f", KNOWN_HOSTS, "-R", vm_ip], capture_output=True)
    secrets = get_secrets_from_vault(vault_path)
    if not secrets:
        return None, "Failed to get secrets from Vault"
    cmd = build_cmd(vm_ip, playbook, secrets, ssh_type, extra, check=True)
    result = subprocess.run(
        cmd, capture_output=True, text=True,
        encoding="utf-8", errors="replace",
        cwd=os.path.dirname(playbook),
        env={**os.environ, "ANSIBLE_FORCE_COLOR": "0", "PYTHONIOENCODING": "utf-8"},
    )
    return result.stdout + result.stderr, None


def run_ansible_stream(job_id):
    """Thuc thi Ansible that va stream log theo tung dong."""
    job = db_get_job(job_id)
    if not job:
        return

    vm_ip      = job["vm_ip"]
    playbook   = job["playbook"]
    vault_path = job["vault_path"]
    ssh_type   = job["ssh_type"]
    extra      = job.get("extra")

    subprocess.run(["ssh-keygen", "-f", KNOWN_HOSTS, "-R", vm_ip], capture_output=True)
    secrets = get_secrets_from_vault(vault_path)
    if not secrets:
        _stream_append(job_id, "ERROR: Failed to get secrets from Vault")
        db_update_job(job_id, status="failed", result="Failed to get secrets from Vault")
        send_telegram(f"Job <b>#{job_id[:8]}</b> FAILED: Cannot get secrets from Vault.")
        return

    cmd = build_cmd(vm_ip, playbook, secrets, ssh_type, extra, check=False)
    print(f"[INFO] Streaming Ansible for job {job_id[:8]} host: {vm_ip}")

    process = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace",
        cwd=os.path.dirname(playbook),
        env={**os.environ, "ANSIBLE_FORCE_COLOR": "0", "PYTHONIOENCODING": "utf-8"},
    )

    full_output = []
    for line in process.stdout:
        line = line.rstrip()
        full_output.append(line)
        _stream_append(job_id, line)

    process.wait()
    result_text = "\n".join(full_output)
    _stream_append(job_id, "__DONE__")

    if process.returncode == 0:
        db_update_job(job_id, status="success", result=result_text)
        send_telegram(
            f"Job <b>#{job_id[:8]}</b> THANH CONG!\n"
            f"Workspace: <b>{job['workspace']}</b>\n"
            f"Host: <code>{vm_ip}</code>"
        )
        if job["workspace"] == "aws-infra":
            t = threading.Thread(target=run_proxmox_with_eip, daemon=True)
            t.start()
    else:
        db_update_job(job_id, status="failed", result=result_text)
        send_telegram(
            f"Job <b>#{job_id[:8]}</b> THAT BAI!\n"
            f"Workspace: <b>{job['workspace']}</b>\n"
            f"Host: <code>{vm_ip}</code>"
        )


def _stream_append(job_id, line):
    if job_id not in stream_buffers:
        stream_buffers[job_id] = []
        stream_locks[job_id]   = threading.Lock()
    with stream_locks[job_id]:
        stream_buffers[job_id].append(line)


def run_proxmox_with_eip():
    print("[INFO] Auto-triggering Proxmox playbook to update WireGuard endpoint...")
    config     = WORKSPACE_CONFIG["proxmox-infra"]
    proxmox_ip = get_ip_from_hcp("proxmox-infra", config["output_key"])
    aws_eip    = get_aws_eip()
    if not proxmox_ip or not aws_eip:
        print("[WARN] Auto-trigger: Missing Proxmox IP or AWS EIP -- skipping.")
        return
    create_approval_job("proxmox-infra", proxmox_ip, f"wg_ec2_endpoint={aws_eip}")


def auto_reject(job_id):
    job = db_get_job(job_id)
    if job and job["status"] == "pending":
        db_update_job(job_id, status="timeout")
        print(f"[INFO] Job {job_id[:8]} auto-rejected after timeout.")
        send_telegram(
            f"Job <b>#{job_id[:8]}</b> het thoi gian 30 phut, tu dong REJECT.\n"
            f"Workspace: <b>{job['workspace']}</b>"
        )


def create_approval_job(workspace_name, vm_ip, extra=None):
    config = WORKSPACE_CONFIG[workspace_name]

    # Cho SSH san sang truoc khi dry run
    ssh_ready = wait_for_ssh(vm_ip)
    if not ssh_ready:
        send_telegram(
            f"Khong the ket noi SSH toi <code>{vm_ip}</code> sau 5 phut.\n"
            f"Workspace: <b>{workspace_name}</b> -- Bo qua."
        )
        return

    print(f"[INFO] Running dry-run for {workspace_name} ({vm_ip})...")
    dry_run_output, err = run_ansible_check(
        vm_ip, config["playbook"], config["vault_path"],
        config["ssh_type"], extra
    )
    if err:
        send_telegram(f"Dry run FAILED cho workspace <b>{workspace_name}</b>: {err}")
        return

    job_id = str(uuid.uuid4())

    job = {
        "id":          job_id,
        "workspace":   workspace_name,
        "description": config["description"],
        "vm_ip":       vm_ip,
        "playbook":    config["playbook"],
        "vault_path":  config["vault_path"],
        "ssh_type":    config["ssh_type"],
        "extra":       extra,
        "dry_run_out": dry_run_output,
        "result":      None,
        "status":      "pending",
        "created_at":  now_str(),
    }
    db_save_job(job)

    # Auto-reject timer
    timer = threading.Timer(APPROVAL_TIMEOUT, auto_reject, args=[job_id])
    timer.daemon = True
    timer.start()
    auto_reject_timers[job_id] = timer

    report_url = f"{WEBHOOK_BASE_URL}/report/{job_id}"
    send_telegram(
        f"Yeu cau Ansible moi can duyet!\n\n"
        f"Job ID: <b>#{job_id[:8]}</b>\n"
        f"Workspace: <b>{workspace_name}</b>\n"
        f"Host: <code>{vm_ip}</code>\n"
        f"Mo ta: {config['description']}\n\n"
        f"Xem va duyet tai:\n{report_url}\n\n"
        f"Tu dong REJECT sau: <b>30 phut</b>"
    )
    print(f"[INFO] Job {job_id[:8]} created, waiting for approval.")


# ── Auth ──────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(f"/login?next={request.path}")
        return f(*args, **kwargs)
    return decorated


# ── HTML Templates ────────────────────────────────────────────

BASE_STYLE = """
<script src="https://cdn.tailwindcss.com"></script>
<style>
  .terminal { background:#1e1e1e; color:#d4d4d4; font-family:'Courier New',monospace;
              font-size:12px; padding:16px; border-radius:12px; overflow-y:auto;
              white-space:pre-wrap; word-break:break-all; }
  .terminal .ok    { color:#4ec9b0; }
  .terminal .changed { color:#dcdcaa; }
  .terminal .failed  { color:#f44747; }
  .terminal .skip    { color:#9cdcfe; }
</style>
"""

LOGIN_HTML = """
<!DOCTYPE html><html lang="vi"><head>
<meta charset="UTF-8"><title>Login - Ansible Approval</title>
""" + BASE_STYLE + """
</head><body class="bg-gray-100 min-h-screen flex items-center justify-center">
  <div class="bg-white rounded-2xl shadow-lg p-8 w-full max-w-md">
    <div class="text-center mb-8">
      <div class="text-4xl mb-2">🔐</div>
      <h1 class="text-2xl font-bold text-gray-800">Ansible Approval Portal</h1>
      <p class="text-gray-500 text-sm mt-1">DevOps HTV</p>
    </div>
    {% if error %}<div class="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg mb-4 text-sm">{{ error }}</div>{% endif %}
    <form method="POST" action="/login">
      <input type="hidden" name="next" value="{{ next }}">
      <div class="mb-4">
        <label class="block text-sm font-medium text-gray-700 mb-1">Username</label>
        <input type="text" name="username" required class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
      </div>
      <div class="mb-6">
        <label class="block text-sm font-medium text-gray-700 mb-1">Password</label>
        <input type="password" name="password" required class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
      </div>
      <button type="submit" class="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2 px-4 rounded-lg transition">Dang nhap</button>
    </form>
  </div>
</body></html>
"""

JOBS_HTML = """
<!DOCTYPE html><html lang="vi"><head>
<meta charset="UTF-8"><title>Jobs - Ansible Approval</title>
""" + BASE_STYLE + """
</head><body class="bg-gray-100 min-h-screen p-6">
<div class="max-w-4xl mx-auto">
  <div class="flex justify-between items-center mb-6">
    <div>
      <h1 class="text-2xl font-bold text-gray-800">Lich su Ansible Jobs</h1>
      <p class="text-gray-500 text-sm">Hien thi 50 jobs gan nhat</p>
    </div>
    <div class="flex gap-3 items-center">
      <a href="/jobs" class="text-sm text-blue-600 hover:underline">Lam moi</a>
      <span class="text-gray-300">|</span>
      <a href="/logout" class="text-sm text-gray-500 hover:text-gray-700">Dang xuat</a>
    </div>
  </div>

  {% if jobs %}
  <div class="space-y-3">
    {% for job in jobs %}
    <a href="/report/{{ job.id }}" class="block bg-white rounded-xl shadow p-4 hover:shadow-md transition">
      <div class="flex justify-between items-center">
        <div>
          <p class="font-semibold text-gray-800">{{ job.workspace }} &mdash; <code class="text-sm">{{ job.vm_ip }}</code></p>
          <p class="text-sm text-gray-500 mt-0.5">{{ job.created_at }} &nbsp;|&nbsp; Job <code>#{{ job.id[:8] }}</code></p>
        </div>
        <div class="flex flex-col items-end gap-1">
          <span class="px-3 py-1 rounded-full text-xs font-semibold
            {% if job.status == 'pending' %}bg-yellow-100 text-yellow-800
            {% elif job.status == 'approved' %}bg-blue-100 text-blue-800
            {% elif job.status == 'success' %}bg-green-100 text-green-800
            {% elif job.status == 'failed' %}bg-red-100 text-red-800
            {% elif job.status == 'rejected' %}bg-gray-100 text-gray-600
            {% elif job.status == 'timeout' %}bg-orange-100 text-orange-700
            {% else %}bg-gray-100 text-gray-600{% endif %}">
            {{ job.status | upper }}
          </span>
        </div>
      </div>
    </a>
    {% endfor %}
  </div>
  {% else %}
  <div class="bg-white rounded-2xl shadow p-12 text-center text-gray-400">
    <div class="text-5xl mb-4">📋</div>
    <p>Chua co job nao.</p>
  </div>
  {% endif %}
</div>
</body></html>
"""

REPORT_HTML = """
<!DOCTYPE html><html lang="vi"><head>
<meta charset="UTF-8"><title>Job #{{ job.id[:8] }} - Ansible Approval</title>
""" + BASE_STYLE + """
</head><body class="bg-gray-100 min-h-screen p-6">
<div class="max-w-4xl mx-auto">

  <!-- Nav -->
  <div class="flex justify-between items-center mb-4">
    <a href="/jobs" class="text-sm text-blue-600 hover:underline">&larr; Tat ca jobs</a>
    <a href="/logout" class="text-sm text-gray-500 hover:text-gray-700">Dang xuat</a>
  </div>

  <!-- Header -->
  <div class="bg-white rounded-2xl shadow p-6 mb-4">
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-bold text-gray-800">Ansible Approval Request</h1>
        <p class="text-gray-500 text-sm">Job: <code class="bg-gray-100 px-2 py-0.5 rounded">{{ job.id[:8] }}</code></p>
      </div>
      <span class="px-3 py-1 rounded-full text-sm font-semibold
        {% if job.status == 'pending' %}bg-yellow-100 text-yellow-800
        {% elif job.status == 'approved' %}bg-blue-100 text-blue-800
        {% elif job.status == 'success' %}bg-green-100 text-green-800
        {% elif job.status == 'failed' %}bg-red-100 text-red-800
        {% elif job.status == 'rejected' %}bg-gray-100 text-gray-600
        {% elif job.status == 'timeout' %}bg-orange-100 text-orange-700
        {% else %}bg-gray-100 text-gray-600{% endif %}">
        {{ job.status | upper }}
      </span>
    </div>
  </div>

  <!-- Info -->
  <div class="bg-white rounded-2xl shadow p-6 mb-4">
    <h2 class="text-base font-semibold text-gray-700 mb-3">Thong tin</h2>
    <div class="grid grid-cols-2 gap-4 text-sm">
      <div><p class="text-gray-400">Workspace</p><p class="font-medium">{{ job.workspace }}</p></div>
      <div><p class="text-gray-400">Mo ta</p><p class="font-medium">{{ job.description }}</p></div>
      <div><p class="text-gray-400">Host IP</p><p class="font-mono font-medium">{{ job.vm_ip }}</p></div>
      <div><p class="text-gray-400">Tao luc</p><p class="font-medium">{{ job.created_at }}</p></div>
    </div>
  </div>

  <!-- Countdown -->
  {% if job.status == 'pending' %}
  <div class="bg-yellow-50 border border-yellow-200 rounded-2xl p-4 mb-4 flex items-center gap-3">
    <span class="text-2xl">⏱</span>
    <div>
      <p class="font-semibold text-yellow-800 text-sm">Thoi gian con lai de duyet</p>
      <p id="countdown" class="text-yellow-700 text-sm font-mono"></p>
    </div>
  </div>
  {% endif %}

  <!-- Dry Run -->
  <div class="bg-white rounded-2xl shadow p-6 mb-4">
    <h2 class="text-base font-semibold text-gray-700 mb-3">Ket qua Dry Run (--check mode)</h2>
    <div class="terminal max-h-80">{{ job.dry_run_out or 'Khong co du lieu.' }}</div>
  </div>

  <!-- Live stream (when approved/running) -->
  {% if job.status == 'approved' %}
  <div class="bg-white rounded-2xl shadow p-6 mb-4">
    <div class="flex items-center gap-2 mb-3">
      <h2 class="text-base font-semibold text-gray-700">Dang chay Ansible...</h2>
      <span class="inline-block w-2 h-2 bg-green-500 rounded-full animate-pulse"></span>
    </div>
    <div id="live-log" class="terminal max-h-96"></div>
  </div>
  <script>
    const logDiv = document.getElementById("live-log");
    const es = new EventSource("/stream/{{ job.id }}");
    es.onmessage = function(e) {
      if (e.data === "__DONE__") {
        es.close();
        setTimeout(() => location.reload(), 2000);
        return;
      }
      logDiv.textContent += e.data + "\\n";
      logDiv.scrollTop = logDiv.scrollHeight;
    };
  </script>
  {% endif %}

  <!-- Result (completed) -->
  {% if job.result and job.status in ['success', 'failed'] %}
  <div class="bg-white rounded-2xl shadow p-6 mb-4">
    <h2 class="text-base font-semibold text-gray-700 mb-3">Ket qua Thuc thi</h2>
    <div class="terminal max-h-96">{{ job.result }}</div>
  </div>
  {% endif %}

  <!-- Actions -->
  {% if job.status == 'pending' %}
  <div class="bg-white rounded-2xl shadow p-6">
    <h2 class="text-base font-semibold text-gray-700 mb-4">Quyet dinh</h2>
    <div class="flex gap-4">
      <form method="POST" action="/approve/{{ job.id }}" class="flex-1">
        <button type="submit" class="w-full bg-green-600 hover:bg-green-700 text-white font-bold py-3 px-6 rounded-xl transition text-base">
          Approve — Chay Ansible
        </button>
      </form>
      <form method="POST" action="/reject/{{ job.id }}" class="flex-1">
        <button type="submit" class="w-full bg-red-500 hover:bg-red-600 text-white font-bold py-3 px-6 rounded-xl transition text-base">
          Reject — Bo qua
        </button>
      </form>
    </div>
  </div>
  {% endif %}

</div>

{% if job.status == 'pending' %}
<script>
  const created  = new Date("{{ job.created_at }}").getTime();
  const timeout  = {{ timeout }};
  function tick() {
    const left = timeout - Math.floor((Date.now() - created) / 1000);
    if (left <= 0) {
      document.getElementById("countdown").textContent = "Da het han — tu dong reject";
      setTimeout(() => location.reload(), 3000);
      return;
    }
    const m = String(Math.floor(left/60)).padStart(2,"0");
    const s = String(left % 60).padStart(2,"0");
    document.getElementById("countdown").textContent = m + ":" + s + " con lai";
  }
  tick(); setInterval(tick, 1000);
</script>
{% endif %}
</body></html>
"""


# ── Routes ────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    next_url = request.args.get("next") or request.form.get("next", "/jobs")
    if request.method == "POST":
        if request.form.get("username") == UI_USERNAME and request.form.get("password") == UI_PASSWORD:
            session["logged_in"] = True
            session["username"]  = request.form.get("username")
            return redirect(next_url)
        return render_template_string(LOGIN_HTML, error="Sai username hoac password.", next=next_url)
    return render_template_string(LOGIN_HTML, error=None, next=next_url)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route("/jobs")
@login_required
def job_list():
    jobs = db_list_jobs()
    return render_template_string(JOBS_HTML, jobs=jobs)


@app.route("/report/<job_id>")
@login_required
def report(job_id):
    job = db_get_job(job_id)
    if not job:
        return "Job not found", 404
    return render_template_string(REPORT_HTML, job=job, timeout=APPROVAL_TIMEOUT)


@app.route("/stream/<job_id>")
@login_required
def stream(job_id):
    """Server-Sent Events stream cho real-time log."""
    def generate():
        sent = 0
        while True:
            buf = stream_buffers.get(job_id, [])
            while sent < len(buf):
                line = buf[sent]
                yield f"data: {line}\n\n"
                sent += 1
                if line == "__DONE__":
                    return
            time.sleep(0.5)
    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/approve/<job_id>", methods=["POST"])
@login_required
def approve(job_id):
    job = db_get_job(job_id)
    if not job or job["status"] != "pending":
        return redirect(f"/report/{job_id}")

    # Cancel auto-reject timer
    if job_id in auto_reject_timers:
        auto_reject_timers[job_id].cancel()

    db_update_job(job_id, status="approved")
    send_telegram(
        f"Job <b>#{job_id[:8]}</b> duoc APPROVE boi <b>{session.get('username')}</b>.\n"
        f"Workspace: <b>{job['workspace']}</b> | Host: <code>{job['vm_ip']}</code>\n"
        f"Dang chay Ansible..."
    )
    stream_buffers[job_id] = []
    stream_locks[job_id]   = threading.Lock()

    t = threading.Thread(target=run_ansible_stream, args=[job_id], daemon=True)
    t.start()
    return redirect(f"/report/{job_id}")


@app.route("/reject/<job_id>", methods=["POST"])
@login_required
def reject(job_id):
    job = db_get_job(job_id)
    if not job or job["status"] != "pending":
        return redirect(f"/report/{job_id}")

    if job_id in auto_reject_timers:
        auto_reject_timers[job_id].cancel()

    db_update_job(job_id, status="rejected")
    send_telegram(
        f"Job <b>#{job_id[:8]}</b> bi REJECT boi <b>{session.get('username')}</b>.\n"
        f"Workspace: <b>{job['workspace']}</b>"
    )
    return redirect(f"/report/{job_id}")


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
                return jsonify({"status": "ignored", "run_status": run_status}), 200

            if is_destroy_run(run_id):
                print("[INFO] Destroy run -- ignoring.")
                return jsonify({"status": "ignored", "reason": "destroy run"}), 200

            config = WORKSPACE_CONFIG.get(workspace_name)
            if not config:
                return jsonify({"status": "ignored", "reason": "unknown workspace"}), 200

            vm_ip = get_ip_from_hcp(workspace_name, config["output_key"])
            if not vm_ip:
                return jsonify({"status": "error", "msg": "Cannot get IP from HCP"}), 500

            extra_vars = None
            if workspace_name == "proxmox-infra":
                aws_eip = get_aws_eip()
                if aws_eip:
                    extra_vars = f"wg_ec2_endpoint={aws_eip}"
                else:
                    print("[INFO] No AWS EIP -- will skip WireGuard role")

            t = threading.Thread(
                target=create_approval_job,
                args=[workspace_name, vm_ip, extra_vars],
                daemon=True
            )
            t.start()

            return jsonify({"status": "pending_approval", "workspace": workspace_name, "vm_ip": vm_ip}), 200

    return jsonify({"status": "ignored"}), 200


@app.route("/health", methods=["GET"])
def health():
    pending = len([j for j in db_list_jobs(100) if j["status"] == "pending"])
    return jsonify({"status": "ok", "pending_jobs": pending}), 200


# ── Init ──────────────────────────────────────────────────────

init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True, threaded=True)
