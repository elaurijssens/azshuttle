# azshuttle

Run [sshuttle](https://sshuttle.readthedocs.io/) over an **Azure Bastion** “native client” tunnel, configured via YAML profiles.

- macOS-friendly
- Azure CLI is the only external dependency for tunneling
- Human-friendly `options` translated to sshuttle **long options** (e.g., `dns` → `--dns`)
- Clean teardown on Ctrl+C / HUP / TERM

## Requirements

- macOS
- Python 3.8+
- [Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli) (`az`)
- [sshuttle](https://sshuttle.readthedocs.io/)

### Install on macOS (Homebrew)
```bash
brew install azure-cli sshuttle