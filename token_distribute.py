"""
token_distribute.py — S3 upload/download and SSH push to remote servers.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile


def upload_to_s3(oauth: dict, provider_profile: str, config: dict) -> bool:
    """Upload token to S3 bucket in versioned envelope format."""
    s3_config = config.get("s3", {})
    bucket = s3_config.get("bucket")
    key = s3_config.get("key", "oauth/tokens.json")
    region = s3_config.get("region", "us-east-2")
    if not bucket:
        return False
    try:
        import boto3
        s3_data = {"version": 1, "profiles": {provider_profile: oauth}}
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump(s3_data, tmp)
        tmp.close()
        s3 = boto3.client("s3", region_name=region)
        s3.upload_file(tmp.name, bucket, key)
        os.unlink(tmp.name)
        return True
    except Exception:
        return False


def download_from_s3(config: dict, provider_profile: str) -> dict | None:
    """Download token from S3. Returns oauth dict or None."""
    s3_config = config.get("s3", {})
    bucket = s3_config.get("bucket")
    key = s3_config.get("key", "oauth/tokens.json")
    region = s3_config.get("region", "us-east-2")
    if not bucket:
        return None
    try:
        import boto3
        tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        tmp.close()
        s3 = boto3.client("s3", region_name=region)
        s3.download_file(bucket, key, tmp.name)
        with open(tmp.name) as f:
            data = json.load(f)
        os.unlink(tmp.name)
        return data.get("profiles", {}).get(provider_profile)
    except Exception:
        return None


def push_to_remote(server_name: str, server_config: dict, oauth: dict, provider_profile: str) -> bool:
    """SSH into remote, write token to all auth-profiles.json files."""
    hostname = server_config.get("hostname")
    ssh_user = server_config.get("ssh_user", "ubuntu")
    ssh_key = os.path.expanduser(server_config.get("ssh_key", "~/.ssh/id_ed25519"))
    instance_id = server_config.get("instance_id")
    if not hostname:
        return False

    # Optional: push SSH key via EC2 Instance Connect
    if instance_id:
        try:
            subprocess.run(
                ["aws", "ec2-instance-connect", "send-ssh-public-key",
                 "--instance-id", instance_id,
                 "--instance-os-user", ssh_user,
                 "--ssh-public-key", f"file://{ssh_key}.pub"],
                capture_output=True, timeout=15, check=True,
            )
        except Exception:
            pass

    # Build remote inject script
    tokens_json = json.dumps(oauth)
    provider_name = provider_profile.split(":")[0]
    inject_script = (
        "import json, glob, os\n"
        f"tokens = json.loads({repr(tokens_json)})\n"
        f"profile_key = {repr(provider_profile)}\n"
        f"provider_name = {repr(provider_name)}\n"
        f"api_key_name = f'{{provider_name}}:api_key'\n"
        "paths = glob.glob(os.path.expanduser('~/.openclaw/auth-profiles.json')) + "
        "glob.glob(os.path.expanduser('~/.openclaw/agents/*/agent/auth-profiles.json'))\n"
        "updated = 0\n"
        "for p in paths:\n"
        "    try:\n"
        "        with open(p) as f:\n"
        "            d = json.load(f)\n"
        "        d.setdefault('profiles', {})[profile_key] = tokens\n"
        "        d.get('profiles', {}).pop(api_key_name, None)\n"
        "        d.setdefault('lastGood', {})[provider_name] = profile_key\n"
        "        with open(p, 'w') as f:\n"
        "            json.dump(d, f)\n"
        "        updated += 1\n"
        "    except:\n"
        "        pass\n"
        "print(f'OK:{updated} files')\n"
    )

    ssh_opts = ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10",
                "-o", "BatchMode=yes", "-i", ssh_key]
    ssh_target = f"{ssh_user}@{hostname}"

    try:
        result = subprocess.run(
            ["ssh"] + ssh_opts + [ssh_target, "python3", "-c", inject_script],
            capture_output=True, text=True, timeout=30,
        )
        return "OK:" in result.stdout
    except Exception:
        return False


def probe_remote_health(server_name: str, server_config: dict, provider_profile: str) -> float:
    """SSH into remote, return hours remaining on best token. Returns -999 on failure."""
    hostname = server_config.get("hostname")
    ssh_user = server_config.get("ssh_user", "ubuntu")
    ssh_key = os.path.expanduser(server_config.get("ssh_key", "~/.ssh/id_ed25519"))
    if not hostname:
        return -999

    probe_script = (
        "import json, time, glob, os\n"
        "paths = glob.glob(os.path.expanduser('~/.openclaw/auth-profiles.json')) + "
        "glob.glob(os.path.expanduser('~/.openclaw/agents/*/agent/auth-profiles.json'))\n"
        f"best = max((json.load(open(p)).get('profiles', {{}}).get({repr(provider_profile)}, {{}}).get('expires', 0) for p in paths), default=0)\n"
        "hrs = round((best - time.time() * 1000) / 3600000, 1)\n"
        "print(hrs)\n"
    )

    try:
        result = subprocess.run(
            ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10",
             "-o", "BatchMode=yes", "-i", ssh_key,
             f"{ssh_user}@{hostname}", "python3", "-c", probe_script],
            capture_output=True, text=True, timeout=20,
        )
        return float(result.stdout.strip())
    except Exception:
        return -999
