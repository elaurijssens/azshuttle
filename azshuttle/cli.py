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
    ssh-key: ~/.ssh/id_rsa_azshuttle  # optional private key for ssh
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
import shutil
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

AZ_KNOWN_HOSTS = Path.home() / ".ssh" / "azshuttle_known_hosts"


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


def cleanup(signum=None, _frame=None, *, exit_code: Optional[int] = None):
    """Tear down sshuttle and the bastion tunnel. Works as signal handler and normal function."""
    global tunnel_proc, sshuttle_proc
    print("Cleaning up...")
    kill_proc_tree(sshuttle_proc, signal.SIGTERM)
    kill_proc_tree(tunnel_proc, signal.SIGTERM)
    time.sleep(0.8)
    kill_proc_tree(sshuttle_proc, signal.SIGKILL)
    kill_proc_tree(tunnel_proc, signal.SIGKILL)

    if exit_code is not None:
        sys.exit(exit_code)
    # if called by signal, return conventional signal exit code
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
    Convert dashed YAML keys to internal snake_case names.
    Only touches known keys.
    """
    mapping = {
        "resource-group": "resource_group",
        "target-vm": "target_vm",
        "target-vm-rg": "target_vm_rg",
        "ssh-user": "ssh_user",
        "ssh-key": "ssh_key",
        "az-bin": "az_bin",
        "sshuttle-bin": "sshuttle_bin",
    }
    out = dict(cfg)
    for d, s in mapping.items():
        if d in out:
            out[s] = out.pop(d)
    return out


def ensure_known_hosts_file():
    AZ_KNOWN_HOSTS.parent.mkdir(parents=True, exist_ok=True)
    # touch with restrictive perms; ignore if it already exists
    try:
        AZ_KNOWN_HOSTS.touch(mode=0o600, exist_ok=True)
    except Exception:
        try:
            os.chmod(AZ_KNOWN_HOSTS, 0o600)
        except Exception:
            pass


def options_include_ssh_cmd(raw_opts) -> bool:
    for item in (raw_opts or []):
        tokens = item if isinstance(item, list) else shlex.split(str(item))
        if not tokens:
            continue
        t0 = tokens[0]
        if t0 in ("--ssh-cmd", "-e"):
            return True
        if t0.startswith("--ssh-cmd"):
            return True
    return False


def options_include_flag(raw_opts, flag: str) -> bool:
    """Return True if options already include a specific long flag (e.g., '--no-sudo-pythonpath')."""
    long = flag if flag.startswith("--") else f"--{flag}"
    for item in (raw_opts or []):
        tokens = item if isinstance(item, list) else shlex.split(str(item))
        if not tokens:
            continue
        if tokens[0] == long or (tokens[0].startswith(long + "=")):
            return True
    return False


def which_or_hint(name: str, custom_path: Optional[str] = None) -> Optional[str]:
    # prefer custom path from YAML if given, else PATH
    if custom_path:
        p = Path(custom_path).expanduser()
        return str(p) if p.exists() and os.access(p, os.X_OK) else None
    return shutil.which(name)


def check_dependencies(az_bin: Optional[str], sshuttle_bin: Optional[str], *, verbose: bool = False) -> dict:
    """
    Return dict with discovered paths and print friendly guidance if missing.
    Keys: {'az': '/path/to/az' | None, 'sshuttle': '/path/to/sshuttle' | None}
    """
    result = {"az": None, "sshuttle": None}
    az_path = which_or_hint("az", az_bin)
    sh_path = which_or_hint("sshuttle", sshuttle_bin)

    if not az_path:
        print("❌ Azure CLI not found.", file=sys.stderr)
        print("   Install on macOS with:", file=sys.stderr)
        print("     brew install azure-cli", file=sys.stderr)
    else:
        result["az"] = az_path
        if verbose:
            print(f"✔ az at {az_path}")

    if not sh_path:
        print("❌ sshuttle not found.", file=sys.stderr)
        print("   Install on macOS with:", file=sys.stderr)
        print("     brew install sshuttle", file=sys.stderr)
        print("   (Or: pipx inject azshuttle sshuttle)", file=sys.stderr)
    else:
        result["sshuttle"] = sh_path
        if verbose:
            # '-V' prints version; don't crash if it doesn't
            try:
                out = subprocess.check_output([sh_path, "-V"], text=True, stderr=subprocess.STDOUT)
                print(f"✔ sshuttle at {sh_path} ({out.strip()})")
            except Exception:
                print(f"✔ sshuttle at {sh_path}")

    return result


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
    except subprocess.CalledProcessError as e:
        die(f"Failed to get VM id via az for VM '{target_vm}' in RG '{rg_lookup}': {e}")

    if not vm_id:
        die(f"Could not resolve VM resource id for VM '{target_vm}' in RG '{rg_lookup}' (empty output).")

    return vm_id


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
    return subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=os.setsid,
        text=True,
    )


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


def start_sshuttle(cfg: dict, profile_name: str) -> subprocess.Popen:
    port = int(cfg["port"])
    try:
        ssh_user = cfg.get("ssh_user") or os.getlogin()
    except Exception:
        ssh_user = cfg.get("ssh_user") or os.environ.get("USER") or os.environ.get("LOGNAME") or "root"

    networks = cfg.get("networks") or []
    if not networks:
        die("No 'networks' provided in profile.")

    raw_opts = cfg.get("options")
    sshuttle_args = build_friendly_long_options(raw_opts)

    # Always add --no-sudo-pythonpath unless user already set it
    if not options_include_flag(raw_opts, "--no-sudo-pythonpath"):
        sshuttle_args.append("--no-sudo-pythonpath")

    # If user didn't supply --ssh-cmd/-e, provide a safe default that isolates host keys per profile.
    if not options_include_ssh_cmd(raw_opts):
        ensure_known_hosts_file()
        host_alias = f"azshuttle-{profile_name}"
        ssh_cmd = [
            "ssh",
            "-o", f"HostKeyAlias={host_alias}",
            "-o", f"UserKnownHostsFile={str(AZ_KNOWN_HOSTS)}",
            "-o", "GlobalKnownHostsFile=/dev/null",
            # Accept first key automatically, then enforce; avoids localhost clashes across profiles
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ServerAliveInterval=30",
            "-o", "ServerAliveCountMax=3",
            "-o", "IdentitiesOnly=yes",
        ]
        if cfg.get("ssh_key"):
            ssh_cmd += ["-i", str(Path(str(cfg["ssh_key"])).expanduser())]
        sshuttle_args += ["-e", " ".join(shlex.quote(x) for x in ssh_cmd)]

    remote = f"{ssh_user}@127.0.0.1:{port}"
    cmd = [SSHUTTLE_BIN] + sshuttle_args + ["-r", remote] + networks

    print("Starting sshuttle:")
    print("  " + " ".join(shlex.quote(x) for x in cmd))
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
    parser.add_argument("profile", nargs="?", help="Profile name under 'profiles' (omit with --doctor)")
    parser.add_argument("-c", "--config", default=str(DEFAULT_CONFIG_PATH), help=f"YAML path (default: {DEFAULT_CONFIG_PATH})")
    parser.add_argument("--doctor", action="store_true", help="Check external dependencies and sudoers guidance")
    args = parser.parse_args()

    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT):
        signal.signal(sig, cleanup)

    cfg_path = Path(args.config).expanduser()

    if args.doctor:
        # Honor global overrides if YAML exists
        az_override = None
        sh_override = None
        if cfg_path.exists():
            data = yaml.safe_load(cfg_path.read_text()) or {}
            global_block = normalize_keys((data.get("global") or {}))
            az_override = global_block.get("az_bin")
            sh_override = global_block.get("sshuttle_bin")

        found = check_dependencies(az_override, sh_override, verbose=True)

        # sudoers guidance
        sh_path = found.get("sshuttle") or sh_override or "sshuttle"
        print("\nSudoers (minimal) for passwordless sshuttle (UNDERSTAND THE RISK):")
        print(f"  # For current user only")
        print(f"  {os.environ.get('USER','your-user')} ALL=(root) NOPASSWD: {sh_path}")
        print("\nNote: azshuttle adds --no-sudo-pythonpath automatically.")
        print("If sshuttle still prompts for sudo, create the file:")
        print("  sudo visudo -f /etc/sudoers.d/azshuttle")
        print("…and paste the line above. Then re-run:")
        print("  azshuttle --doctor\n")
        return

    if not args.profile:
        die("Profile is required unless you use --doctor.")

    cfg = load_profile(cfg_path, args.profile)

    # Preflight checks using resolved binaries (from YAML globals)
    check_dependencies(AZ_BIN, SSHUTTLE_BIN)

    # Warn if ssh_key exists but has loose perms
    if cfg.get("ssh_key"):
        key_path = Path(str(cfg["ssh_key"])).expanduser()
        if key_path.exists():
            try:
                mode = key_path.stat().st_mode & 0o777
                if mode & 0o077:
                    print(f"⚠️  SSH key {key_path} has permissive mode {oct(mode)}; recommend chmod 600 {key_path}", file=sys.stderr)
            except Exception:
                pass

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
            cleanup(exit_code=1)

    print("✅ Tunnel ready. Launching sshuttle...")
    sshuttle_proc = start_sshuttle(cfg, args.profile)

    # Wait and print sudo guidance if it fails
    out, err = sshuttle_proc.communicate()
    code = sshuttle_proc.returncode

    if code == 0:
        if out:
            print(out, end="")
        cleanup(exit_code=0)
    else:
        if err:
            print(err, file=sys.stderr, end="")
        # Heuristic: permission / sudo issues on macOS sshuttle often say "Operation not permitted"
        lower = (err or "").lower()
        if ("permission" in lower) or ("operation not permitted" in lower) or ("pfctl" in lower) or ("sudo" in lower):
            user = os.environ.get("USER") or "your-user"
            print("\n---", file=sys.stderr)
            print("sshuttle likely needed elevated privileges and failed.", file=sys.stderr)
            print("Create a minimal sudoers entry to allow passwordless use (UNDERSTAND THE RISK):", file=sys.stderr)
            # Use discovered path if possible
            sh_path = which_or_hint("sshuttle", SSHUTTLE_BIN) or SSHUTTLE_BIN
            print(f"\n  {user} ALL=(root) NOPASSWD: {sh_path}\n", file=sys.stderr)
            print("azshuttle already adds --no-sudo-pythonpath automatically.", file=sys.stderr)
            print("Install with: sudo visudo -f /etc/sudoers.d/azshuttle", file=sys.stderr)
        cleanup(exit_code=code)


def run():
    main()


if __name__ == "__main__":
    run()