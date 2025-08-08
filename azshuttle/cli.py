#!/usr/bin/env python3
import argparse
import os
import shlex
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

try:
    import yaml
except ImportError:
    print("Missing dependency: PyYAML. Install with: pip3 install pyyaml", file=sys.stderr)
    sys.exit(1)

DEFAULT_CONFIG_PATH = Path.home() / ".ssh" / "sshvpn.yml"

tunnel_proc = None
sshuttle_proc = None

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

def cleanup(signum=None, frame=None):
    global tunnel_proc, sshuttle_proc

    def kill_proc_tree(p: subprocess.Popen | None, sig=signal.SIGTERM):
        if p and p.poll() is None:
            try:
                os.killpg(os.getpgid(p.pid), sig)
            except Exception:
                try:
                    p.terminate()
                except Exception:
                    pass

    print("Cleaning up...")
    kill_proc_tree(sshuttle_proc, signal.SIGTERM)
    kill_proc_tree(tunnel_proc, signal.SIGTERM)
    time.sleep(0.8)
    kill_proc_tree(sshuttle_proc, signal.SIGKILL)
    kill_proc_tree(tunnel_proc, signal.SIGKILL)
    sys.exit(0 if signum is None else 128 + (signum % 128))

def start_bastion_tunnel(cfg: dict) -> subprocess.Popen | None:
    port = int(cfg["port"])
    if is_port_open(port):
        print(f"Port {port} already open; assuming Bastion tunnel exists.")
        return None

    az_bin = cfg.get("az_bin", "az")
    rg = cfg["resource_group"]
    bastion = cfg["bastion"]
    vm_name = cfg["target_vm"]

    try:
        vm_id = subprocess.check_output(
            [az_bin, "vm", "show", "-g", rg, "-n", vm_name, "--query", "id", "-o", "tsv"],
            text=True
        ).strip()
        if not vm_id:
            die("Could not resolve VM resource id (empty output).")
    except subprocess.CalledProcessError as e:
        die(f"Failed to get VM id via az: {e}")

    cmd = [
        az_bin, "network", "bastion", "tunnel",
        "--name", bastion,
        "--resource-group", rg,
        "--target-resource-id", vm_id,
        "--resource-port", "22",
        "--port", str(port),
    ]
    print("Starting Azure Bastion tunnel...")
    return subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=os.setsid,  # new process group for clean kill
        text=True,
    )

def build_friendly_long_options(raw_opts) -> list[str]:
    """
    Turn friendly items like:
      - dns
      - auto-hosts
      - exclude 192.168.1.0/24
    into:
      --dns
      --auto-hosts
      --exclude 192.168.1.0/24

    If an item already starts with '--', pass it through.
    Supports either strings or lists (already-tokenized).
    """
    args: list[str] = []
    for item in (raw_opts or []):
        tokens = item if isinstance(item, list) else shlex.split(str(item))
        if not tokens:
            continue
        head, rest = tokens[0], tokens[1:]

        if head.startswith("--"):
            # Already a long option; pass through as-is
            args.extend([head, *rest])
            continue

        # Friendly name -> kebab-case long option
        # e.g. "auto_hosts" or "auto hosts" -> "--auto-hosts"
        kebab = head.replace("_", "-")
        args.append(f"--{kebab}")
        args.extend(rest)
    return args

def start_sshuttle(cfg: dict) -> subprocess.Popen:
    sshuttle_bin = cfg.get("sshuttle_bin", "sshuttle")
    port = int(cfg["port"])
    # getlogin() can fail in daemons; fall back to environment
    try:
        ssh_user = cfg.get("ssh_user") or os.getlogin()
    except Exception:
        ssh_user = cfg.get("ssh_user") or os.environ.get("USER") or os.environ.get("LOGNAME") or "root"

    networks = cfg.get("networks") or []
    if not networks:
        die("No 'networks' provided in profile.")

    sshuttle_args = build_friendly_long_options(cfg.get("options"))

    remote = f"{ssh_user}@127.0.0.1:{port}"
    cmd = [sshuttle_bin] + sshuttle_args + ["-r", remote] + networks

    print("Starting sshuttle:")
    print("  " + " ".join(shlex.quote(x) for x in cmd))
    return subprocess.Popen(
        cmd,
        preexec_fn=os.setsid,  # new pgid for clean kill
        text=True,
    )

def load_profile(cfg_path: Path, profile: str) -> dict:
    if not cfg_path.exists():
        die(f"Config file not found: {cfg_path}")
    with cfg_path.open("r") as f:
        data = yaml.safe_load(f) or {}
    if profile not in data:
        die(f"Profile '{profile}' not found in {cfg_path}")
    return data[profile]

def main():
    parser = argparse.ArgumentParser(
        description="sshuttle over Azure Bastion, configured via YAML."
    )
    parser.add_argument("profile", help="Profile key in the YAML (e.g. 'myconfig').")
    parser.add_argument(
        "-c", "--config",
        default=str(DEFAULT_CONFIG_PATH),
        help=f"Path to YAML (default: {DEFAULT_CONFIG_PATH})"
    )
    args, unknown = parser.parse_known_args()
    if unknown:
        print(f"Note: ignoring extra CLI args {unknown}. Put sshuttle flags in YAML 'options'.", file=sys.stderr)

    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT):
        signal.signal(sig, cleanup)

    cfg = load_profile(Path(args.config).expanduser(), args.profile)

    for key in ("resource_group", "bastion", "target_vm", "port"):
        if key not in cfg:
            die(f"Missing required key in profile: {key}")

    timeout = int(cfg.get("timeout", 10))
    port = int(cfg["port"])

    global tunnel_proc, sshuttle_proc
    tunnel_proc = start_bastion_tunnel(cfg)

    if not is_port_open(port):
        if not tunnel_proc:
            die(f"Port {port} is not open and tunnel wasn't started.")
        print(f"Waiting up to {timeout}s for port {port}...")
        if not wait_for_port(port, timeout):
            print(f"❌ Port {port} did not open within {timeout} seconds.", file=sys.stderr)
            cleanup()
            return

    print("✅ Tunnel ready. Launching sshuttle...")
    sshuttle_proc = start_sshuttle(cfg)

    try:
        exit_code = sshuttle_proc.wait()
        print(f"sshuttle exited with code {exit_code}")
    finally:
        cleanup()

def run():
    main()

if __name__ == "__main__":
    main()
