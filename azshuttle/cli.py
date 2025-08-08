#!/usr/bin/env python3
"""
azshuttle: run sshuttle over an Azure Bastion tunnel using YAML profiles.

YAML layout (dashed keys only):

global:
  az-bin: az
  sshuttle-bin: sshuttle
  timeout: 10
  ssh-user: myuser
  defaults:
    resource-group: rg-common
    bastion: bas-common
  options:
    - dns

profiles:
  prod:
    resource-group: rg-prod
    bastion: bas-prod
    target-vm: vm-prod
    target-vm-rg: rg-prod-vms   # optional, if VM in different RG
    port: 2222
    networks:
      - 172.16.0.0/12
    options:
      - auto-hosts
      - exclude 192.168.1.0/24
"""

import argparse
import os
import shlex
import signal
import socket
import subprocess
import sys
import time
from copy import deepcopy
from pathlib import Path
from typing import Optional

import yaml

DEFAULT_CONFIG_PATH = Path.home() / ".ssh" / "azshuttle.yml"

# Set from YAML global block (dashed keys)
AZ_BIN = "az"
SSHUTTLE_BIN = "sshuttle"

tunnel_proc: Optional[subprocess.Popen] = None
sshuttle_proc: Optional[subprocess.Popen] = None


# ---------- Utilities ----------

def is_port_open(port: int, host="127.0.0.1", timeout=0.4) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def wait_for_port(port: int, timeout_s: int) -> bool:
    start = time.time()
    while time.time() - start < timeout_s:
        if is_port_open(port):
            return True
        time.sleep(0.25)
    return False


def die(msg: str, code: int = 1):
    print(f"❌ {msg}", file=sys.stderr)
    sys.exit(code)


def kill_proc_tree(p: Optional[subprocess.Popen], sig=signal.SIGTERM) -> None:
    if p is not None and p.poll() is None:
        try:
            os.killpg(os.getpgid(p.pid), sig)
        except Exception:
            try:
                p.terminate()
            except Exception:
                pass


def cleanup(signum=None, frame=None):
    global tunnel_proc, sshuttle_proc
    print("Cleaning up...")
    kill_proc_tree(sshuttle_proc, signal.SIGTERM)
    kill_proc_tree(tunnel_proc, signal.SIGTERM)
    time.sleep(0.8)
    kill_proc_tree(sshuttle_proc, signal.SIGKILL)
    kill_proc_tree(tunnel_proc, signal.SIGKILL)
    sys.exit(0 if signum is None else 128 + (signum % 128))


def deep_merge(a: dict, b: dict) -> dict:
    out = deepcopy(a) if a else {}
    for k, v in (b or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = deepcopy(v)
    return out


def normalize_keys(cfg: dict) -> dict:
    """
    Convert dashed YAML keys to the internal snake_case names the code uses.
    Only touches known keys.
    """
    mapping = {
        "resource-group": "resource_group",
        "target-vm": "target_vm",
        "target-vm-rg": "target_vm_rg",
        "ssh-user": "ssh_user",
        "az-bin": "az_bin",
        "sshuttle-bin": "sshuttle_bin",
    }
    out = dict(cfg)
    for d, s in mapping.items():
        if d in out:
            out[s] = out.pop(d)
    return out


# ---------- Core logic ----------

def resolve_vm_id(resource_group: str, target_vm: str, target_vm_rg: Optional[str]) -> str:
    # Direct resource ID?
    if target_vm.startswith("/subscriptions/"):
        return target_vm

    rg_lookup = target_vm_rg or resource_group
    try:
        vm_id = subprocess.check_output(
            [AZ_BIN, "vm", "show", "-g", rg_lookup, "-n", target_vm, "--query", "id", "-o", "tsv"],
            text=True
        ).strip()
        if not vm_id:
            die(f"Could not resolve VM resource id for VM '{target_vm}' in RG '{rg_lookup}' (empty output).")
        return vm_id
    except subprocess.CalledProcessError as e:
        die(f"Failed to get VM id via az for VM '{target_vm}' in RG '{rg_lookup}': {e}")


def start_bastion_tunnel(cfg: dict) -> Optional[subprocess.Popen]:
    port = int(cfg["port"])
    if is_port_open(port):
        print(f"Port {port} already open; assuming Bastion tunnel exists.")
        return None

    vm_id = resolve_vm_id(cfg["resource_group"], cfg["target_vm"], cfg.get("target_vm_rg"))

    cmd = [
        AZ_BIN, "network", "bastion", "tunnel",
        "--name", cfg["bastion"],
        "--resource-group", cfg["resource_group"],
        "--target-resource-id", vm_id,
        "--resource-port", "22",
        "--port", str(port),
    ]
    print("Starting Azure Bastion tunnel...")
    return subprocess.Popen(cmd, preexec_fn=os.setsid, text=True)


def build_friendly_long_options(raw_opts) -> list[str]:
    """
    'dns' -> --dns
    'auto-hosts' -> --auto-hosts
    'exclude 192.168.1.0/24' -> --exclude 192.168.1.0/24
    If item already starts with '--', pass-through.
    """
    args: list[str] = []
    for item in (raw_opts or []):
        tokens = item if isinstance(item, list) else shlex.split(str(item))
        if not tokens:
            continue
        head, rest = tokens[0], tokens[1:]
        if head.startswith("--"):
            args.extend([head, *rest])
        else:
            kebab = head.replace("_", "-")
            args.append(f"--{kebab}")
            args.extend(rest)
    return args


def start_sshuttle(cfg: dict) -> subprocess.Popen:
    port = int(cfg["port"])
    try:
        ssh_user = cfg.get("ssh_user") or os.getlogin()
    except Exception:
        ssh_user = cfg.get("ssh_user") or os.environ.get("USER") or os.environ.get("LOGNAME") or "root"

    networks = cfg.get("networks") or []
    if not networks:
        die("No 'networks' provided in profile.")

    sshuttle_args = build_friendly_long_options(cfg.get("options"))

    remote = f"{ssh_user}@127.0.0.1:{port}"
    cmd = [SSHUTTLE_BIN] + sshuttle_args + ["-r", remote] + networks

    print("Starting sshuttle:")
    print("  " + " ".join(shlex.quote(x) for x in cmd))
    # Capture output so we can print helpful sudo guidance if it fails
    return subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=os.setsid,
        text=True,
    )


def load_profile(cfg_path: Path, profile: str) -> dict:
    global AZ_BIN, SSHUTTLE_BIN

    if not cfg_path.exists():
        die(f"Config file not found: {cfg_path}")
    with cfg_path.open("r") as f:
        data = yaml.safe_load(f) or {}

    global_block = data.get("global") or {}
    profiles = data.get("profiles") or {}
    if profile not in profiles:
        die(f"Profile '{profile}' not found in {cfg_path}")

    # Normalize dashed keys for global block
    global_block = normalize_keys(global_block)
    defaults = normalize_keys(global_block.get("defaults") or {})

    # Binaries from global
    AZ_BIN = global_block.get("az_bin", AZ_BIN)
    SSHUTTLE_BIN = global_block.get("sshuttle_bin", SSHUTTLE_BIN)

    # Merge defaults with specific profile
    prof_raw = normalize_keys(profiles[profile])
    merged = deep_merge(defaults, prof_raw)

    # Merge options (global first)
    merged["options"] = (global_block.get("options") or []) + (prof_raw.get("options") or [])

    # Inherit timeout / ssh_user if missing
    if "timeout" not in merged and "timeout" in global_block:
        merged["timeout"] = global_block["timeout"]
    if "ssh_user" not in merged and "ssh_user" in global_block:
        merged["ssh_user"] = global_block["ssh_user"]

    return merged


def main():
    parser = argparse.ArgumentParser(description="sshuttle over Azure Bastion, configured via YAML.")
    parser.add_argument("profile", help="Profile name under 'profiles'")
    parser.add_argument("-c", "--config", default=str(DEFAULT_CONFIG_PATH), help=f"YAML path (default: {DEFAULT_CONFIG_PATH})")
    args = parser.parse_args()

    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT):
        signal.signal(sig, cleanup)

    cfg = load_profile(Path(args.config).expanduser(), args.profile)

    for key in ("resource_group", "bastion", "target_vm", "port"):
        if key not in cfg:
            die(f"Missing required key: {key}")

    timeout = int(cfg.get("timeout", 10))
    port = int(cfg["port"])

    global tunnel_proc, sshuttle_proc
    tunnel_proc = start_bastion_tunnel(cfg)

    if not is_port_open(port):
        if not tunnel_proc:
            die(f"Port {port} is not open and tunnel wasn't started.")
        print(f"Waiting up to {timeout}s for port {port}...")
        if not wait_for_port(port, timeout):
            die(f"Port {port} did not open within {timeout} seconds.")

    print("✅ Tunnel ready. Launching sshuttle...")
    sshuttle_proc = start_sshuttle(cfg)

    # Wait and print sudo guidance if it fails
    out, err = sshuttle_proc.communicate()
    code = sshuttle_proc.returncode

    if code == 0:
        print(out, end="")
    else:
        # Heuristic: permission / sudo issues on macOS sshuttle often say "Operation not permitted"
        lower = (err or "").lower()
        print(err, file=sys.stderr, end="")
        if ("permission" in lower) or ("operation not permitted" in lower) or ("pfctl" in lower) or ("sudo" in lower):
            user = os.environ.get("USER") or "your-user"
            print("\n---", file=sys.stderr)
            print("It looks like sshuttle needed elevated privileges and failed.", file=sys.stderr)
            print("You can create a dedicated sudoers entry so sshuttle can run without prompting:", file=sys.stderr)
            print(f"\n  {SSHUTTLE_BIN} --sudoers-no-modify --sudoers-user {shlex.quote(user)} | sudo tee /etc/sudoers.d/sshuttle >/dev/null", file=sys.stderr)
            print("\n⚠️  Warning: sshuttle’s sudoers helper itself notes this is INSECURE — it can be abused to run arbitrary commands as root.", file=sys.stderr)
            print("Only do this if you understand the risk and trust your environment.", file=sys.stderr)
        sys.exit(code)


def run():
    main()


if __name__ == "__main__":
    run()