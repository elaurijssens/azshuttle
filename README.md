# azshuttle

Run [sshuttle](https://sshuttle.readthedocs.io/) over an **Azure Bastion** “native client” tunnel, configured via YAML.

- macOS-friendly
- **Dashed-key YAML** with `global` + `profiles`
- Per-profile SSH host key isolation (no more `localhost` clashes)
- Optional `ssh-key` per profile
- Adds `--no-sudo-pythonpath` automatically
- Clean teardown on Ctrl+C / HUP / TERM
- `azshuttle --doctor` checks deps and prints **minimal sudoers** guidance

## Requirements

- macOS
- Python 3.8+
- [Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli) (`az`)
- [sshuttle](https://sshuttle.readthedocs.io/)

Install on macOS:
```bash
brew install azure-cli sshuttle
```

## Install with `pipx`

From a Git repository:
```bash
pipx install git+https://github.com/<youruser>/azshuttle.git
```

Upgrade:
```bash
pipx upgrade azshuttle
```

## Config file

Default location: `~/.ssh/azshuttle.yml` (override with `-c`).

### Structure

```yaml
global:
  az-bin: /opt/homebrew/bin/az         # optional; default: "az"
  sshuttle-bin: /opt/homebrew/bin/sshuttle  # optional; default: "sshuttle"
  timeout: 12                          # optional; default: 10
  ssh-user: emma                       # optional default user
  defaults:                            # optional defaults for all profiles
    resource-group: rg-common
    bastion: bas-common
  options:                             # optional global sshuttle options (prepended)
    - dns

profiles:
  prod:
    resource-group: rg-prod-networking
    bastion: bas-prod-bastion
    target-vm: vm-prod-jumphost              # or a full /subscriptions/... resource ID
    # target-vm-rg: rg-prod-compute          # only needed if target-vm is a NAME in a different RG
    port: 2222
    ssh-key: ~/.ssh/id_rsa_azshuttle         # optional; used with -i and IdentitiesOnly=yes
    networks:
      - 172.16.0.0/12
      - 192.168.0.0/16
    options:
      - auto-hosts
      - auto-nets
      - exclude 192.168.1.0/24
      - exclude 192.168.4.0/22

  lab:
    target-vm: /subscriptions/.../resourceGroups/rg-lab/providers/Microsoft.Compute/virtualMachines/vm-lab
    port: 2323
    networks:
      - 10.0.0.0/8
```

### Keys

- `resource-group` (required): Azure RG containing Bastion (and VM if `target-vm-rg` not set)
- `bastion` (required): Bastion resource name
- `target-vm` (required): VM **name** *or* **full resource ID**
- `target-vm-rg` (optional): VM’s RG if VM is in a different RG than Bastion
- `port` (required): local TCP port for the Bastion tunnel
- `networks` (required): list of CIDRs to route via sshuttle
- `ssh-user` (optional): SSH username; falls back to current macOS user
- `ssh-key` (optional): path to private key; used with `-i` and `IdentitiesOnly=yes`
- `options` (optional): **friendly long options** for sshuttle:
    - `dns` → `--dns`
    - `auto-hosts` → `--auto-hosts`
    - `exclude 192.168.1.0/24` → `--exclude 192.168.1.0/24`
    - Items starting with `--` are passed through as-is
- `az-bin`, `sshuttle-bin` (optional): override binary paths

> Note: azshuttle auto-adds `--no-sudo-pythonpath` unless you already set it in `options`.

## Usage

```bash
azshuttle --doctor                 # check deps and sudoers guidance
azshuttle prod                     # use profile 'prod' from default config
azshuttle -c ~/custom.yml prod     # alternate config path
```

On first connect, host keys are stored using a per-profile alias (`HostKeyAlias=azshuttle-<profile>`) in `~/.ssh/azshuttle_known_hosts`, with `StrictHostKeyChecking=accept-new`.

## Sudo / Permissions

`sshuttle` often needs elevated privileges to manage the firewall on macOS. If it fails with a permission error, create a **minimal** sudoers entry so your user can run `sshuttle` without a password:

```text
<your-user> ALL=(root) NOPASSWD: /opt/homebrew/bin/sshuttle
```

Create it with:

```bash
sudo visudo -f /etc/sudoers.d/azshuttle
# paste the line above and save
```

Then verify with:

```bash
azshuttle --doctor
```

azshuttle already adds `--no-sudo-pythonpath` to avoid the broader (and riskier) sudoers content suggested by `sshuttle --sudoers-no-modify`.

## Signals & Cleanup

- On **Ctrl+C**, **SIGHUP**, **SIGTERM**, or **SIGQUIT**, azshuttle terminates both `sshuttle` and the `az network bastion tunnel` it started.
- If the port is already open at startup, azshuttle won’t start a duplicate tunnel.

## Troubleshooting

- **Auth**: `az login` first and ensure access to the target RG/VM.
- **SSH key**: if set, ensure `chmod 600` on the key file.
- **Port busy**: change `port` in the profile or stop the existing tunnel.
