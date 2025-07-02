# BadSuccessor

## 📝 Description 
This script automates the exploitation of the BadSuccessor vulnerability, and can be executed from a Windows host that is not domain-joined. BadSuccessor allows domain accounts with the ability to create gMSA accounts to perform privilege escalation, providing access to the password hash of any domain account (including DA accounts). 

Akamai researcher Yuval Gordon discovered BadSuccessor and published a very comprehensive explaination of the vulnerability ([More Reading](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory#conclusion)). This script is not intended to replace or take credit for Yuval's work. Instead, this script automates all of the steps involved in exploiting BadSuccessor and also allows exploitation from a host that is not domain-joined. 

![img.png](img.png)

## 🧰 Requirements

- Python 3.8+
- Windows environment (PowerShell required)
- Windows RSAT Tools Enabled (Windows Feature) - Installation instructions available [here](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remote-server-administration-tools)
- Modules:
  - `ldap3` - Automatically installed if using pipx. Otherwise, needs a `pip install ldap3`
- Domain user credentials that can create a dMSA account, either via the *Create msDS-DelegatedManagedServiceAccount* or *Create All Child Objects* on an OU.

## 📦 Installation

```bash
pipx install https://github.com/Sentinel-Pen-Testers/BadSuccessor
```
Alternatively, the script can be run directly, as long as the Python library *ldap3* is installed.

## 🚀 Usage

### Basic Command

```bash
python dmsa_tool.py \
  -u LukeAdmin \
  -p 'SuperSecret!' \
  -d example.com \
  -dc dc01.example.com \
  -ou Users
```

### Arguments

| Argument              | Required | Description                                                            |
|-----------------------|----------|------------------------------------------------------------------------|
| `-u`, `--username`    | ✅       | Domain user with rights to create gMSAs                                |
| `-p`, `--password`    | ✅       | Password for the above user                                            |
| `-d`, `--domain`      | ✅       | AD domain (e.g., `example.com`)                                        |
| `-dc`, `--domain_controller` | ✅ | Domain Controller FQDN/IP                                              |
| `-ou`, `--org_unit`   | ✅       | Organizational Unit to place the dMSA                                  |
| `-da`, `--dmsa_account_name` | ❌ | Name of the dMSA account (default: `pentest_dmsa`)                     |
| `-t`, `--target_account` | ❌    | Domain account to link or extract hash from (default: `Administrator`) |
| `-db`, `--debug`      | ❌       | Enable verbose output for troubleshooting                              |

## ⚠️ Notes & Considerations

- This script is not great in its current form. There are a few functions that are AI slop. The author currently doesn't have time to clean up the script (so pull requests are always appreciate).
- Ideally, the script would ideally be designed in one of two different ways:
  - Pure Python, allowing execution on Linux systems. 
  - Pure PowerShell, eliminating Python as a dependency.
- This script is intended for authorized penetration testing, red teaming, or domain security automation.