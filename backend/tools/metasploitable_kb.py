"""
tools/metasploitable_kb.py — Metasploitable 2 known vulnerability knowledge base.

Metasploitable 2 runs intentionally vulnerable services. The NVD keyword
search is unreliable at finding these because they are indexed under very
specific CPE names. This module provides a curated list of the well-known
CVEs and their corresponding Metasploit modules so the vuln agent can
inject them whenever those services are detected during recon.
"""

from typing import Optional


# Mapping: (service_keyword, port) → list of known CVE findings
# service_keyword is matched case-insensitively against the detected service name.
# port=None means match on service name alone regardless of port.
METASPLOITABLE2_KB: list[dict] = [
    # ── vsftpd 2.3.4 backdoor ─────────────────────────────────────────
    {
        "match_service": "ftp",
        "match_port": 21,
        "match_version_contains": "2.3.4",
        "cve_id": "CVE-2011-2523",
        "cvss_v3": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "critical",
        "description": "vsftpd 2.3.4 contains a backdoor that opens a root shell on port 6200 when ':)' is appended to the username during login.",
        "exploit_available": True,
        "msf_module": "exploit/unix/ftp/vsftpd_234_backdoor",
        "exploit_complexity": "low",
        "attack_vector": "network",
        "privileges_required": "none",
        "user_interaction": "none",
        "owasp_category": "A06:2021 – Vulnerable and Outdated Components",
        "cwe": "CWE-78",
        "impact": "Unauthenticated remote root shell access via triggered backdoor on port 6200.",
        "ranking_reason": "Known backdoor, trivially exploitable, grants immediate root shell.",
        "remediation_short": "Remove vsftpd 2.3.4 and replace with a patched version.",
        "remediation_package": "vsftpd",
        "remediation_cmd": "apt-get remove vsftpd && apt-get install vsftpd",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2011-2523",
            "https://www.exploit-db.com/exploits/17491",
        ],
    },
    # ── Samba 3.x username map script (ms08_067 of Linux) ────────────
    {
        "match_service": "samba",
        "match_port": 445,
        "match_version_contains": None,
        "cve_id": "CVE-2007-2447",
        "cvss_v3": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "severity": "critical",
        "description": "Samba 3.0.20 through 3.0.25rc3 username map script allows remote command injection through shell metacharacters passed in the username field.",
        "exploit_available": True,
        "msf_module": "exploit/multi/samba/usermap_script",
        "exploit_complexity": "low",
        "attack_vector": "network",
        "privileges_required": "none",
        "user_interaction": "none",
        "owasp_category": "A03:2021 – Injection",
        "cwe": "CWE-78",
        "impact": "Unauthenticated remote root shell via OS command injection in Samba username map script.",
        "ranking_reason": "Trivially exploitable with a one-command Metasploit module, grants root.",
        "remediation_short": "Upgrade Samba to 3.0.26 or later.",
        "remediation_package": "samba",
        "remediation_cmd": "apt-get update && apt-get install --only-upgrade samba",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2007-2447",
            "https://www.exploit-db.com/exploits/16320",
        ],
    },
    # ── Samba port 139 ────────────────────────────────────────────────
    {
        "match_service": "netbios",
        "match_port": 139,
        "match_version_contains": None,
        "cve_id": "CVE-2007-2447",
        "cvss_v3": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "severity": "critical",
        "description": "Samba 3.0.20 through 3.0.25rc3 username map script allows remote command injection through shell metacharacters passed in the username field.",
        "exploit_available": True,
        "msf_module": "exploit/multi/samba/usermap_script",
        "exploit_complexity": "low",
        "attack_vector": "network",
        "privileges_required": "none",
        "user_interaction": "none",
        "owasp_category": "A03:2021 – Injection",
        "cwe": "CWE-78",
        "impact": "Unauthenticated remote root shell via OS command injection in Samba.",
        "ranking_reason": "Trivially exploitable on NetBIOS port, same as port 445 vector.",
        "remediation_short": "Upgrade Samba to 3.0.26 or later.",
        "remediation_package": "samba",
        "remediation_cmd": "apt-get update && apt-get install --only-upgrade samba",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2007-2447",
        ],
    },
    # ── UnrealIRCd 3.2.8.1 backdoor ──────────────────────────────────
    {
        "match_service": "irc",
        "match_port": 6667,
        "match_version_contains": None,
        "cve_id": "CVE-2010-2075",
        "cvss_v3": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "critical",
        "description": "UnrealIRCd 3.2.8.1 contains a backdoor introduced into the source code that allows remote command execution.",
        "exploit_available": True,
        "msf_module": "exploit/unix/irc/unreal_ircd_3281_backdoor",
        "exploit_complexity": "low",
        "attack_vector": "network",
        "privileges_required": "none",
        "user_interaction": "none",
        "owasp_category": "A06:2021 – Vulnerable and Outdated Components",
        "cwe": "CWE-506",
        "impact": "Unauthenticated remote code execution as the IRC server process user.",
        "ranking_reason": "Known supply-chain backdoor, single-command exploitation via Metasploit.",
        "remediation_short": "Replace UnrealIRCd 3.2.8.1 with a clean, verified version.",
        "remediation_package": "unrealircd",
        "remediation_cmd": "apt-get remove unrealircd",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2010-2075",
            "https://www.exploit-db.com/exploits/13853",
        ],
    },
    # ── Distcc remote code execution ─────────────────────────────────
    {
        "match_service": "distcc",
        "match_port": 3632,
        "match_version_contains": None,
        "cve_id": "CVE-2004-2687",
        "cvss_v3": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "critical",
        "description": "distcc 2.x, when not configured to restrict access, allows remote attackers to execute arbitrary commands via compilation jobs.",
        "exploit_available": True,
        "msf_module": "exploit/unix/misc/distcc_exec",
        "exploit_complexity": "low",
        "attack_vector": "network",
        "privileges_required": "none",
        "user_interaction": "none",
        "owasp_category": "A05:2021 – Security Misconfiguration",
        "cwe": "CWE-264",
        "impact": "Unauthenticated remote command execution as the daemon user.",
        "ranking_reason": "Exposed distcc port with no access control, trivially exploitable.",
        "remediation_short": "Disable distcc or restrict access with firewall rules.",
        "remediation_package": "distcc",
        "remediation_cmd": "ufw deny 3632/tcp",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2004-2687",
        ],
    },
    # ── Java RMI Server ───────────────────────────────────────────────
    {
        "match_service": "rmiregistry",
        "match_port": 1099,
        "match_version_contains": None,
        "cve_id": "CVE-2011-3556",
        "cvss_v3": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "critical",
        "description": "The Java RMI registry allows remote code execution when the RMI server is misconfigured to allow loading classes from remote URLs.",
        "exploit_available": True,
        "msf_module": "exploit/multi/misc/java_rmi_server",
        "exploit_complexity": "low",
        "attack_vector": "network",
        "privileges_required": "none",
        "user_interaction": "none",
        "owasp_category": "A05:2021 – Security Misconfiguration",
        "cwe": "CWE-502",
        "impact": "Unauthenticated remote code execution via deserialization in Java RMI.",
        "ranking_reason": "Exposed Java RMI registry on Metasploitable is universally exploitable.",
        "remediation_short": "Disable Java RMI registry or restrict to localhost.",
        "remediation_package": None,
        "remediation_cmd": "iptables -A INPUT -p tcp --dport 1099 -j DROP",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2011-3556",
        ],
    },
    # ── PostgreSQL default credentials ────────────────────────────────
    {
        "match_service": "postgresql",
        "match_port": 5432,
        "match_version_contains": None,
        "cve_id": "CVE-1999-0502",
        "cvss_v3": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "critical",
        "description": "PostgreSQL is accessible with default credentials (postgres:postgres), allowing full database access and OS command execution via COPY TO/FROM PROGRAM.",
        "exploit_available": True,
        "msf_module": "exploit/linux/postgres/postgres_payload",
        "exploit_complexity": "low",
        "attack_vector": "network",
        "privileges_required": "none",
        "user_interaction": "none",
        "owasp_category": "A07:2021 – Identification and Authentication Failures",
        "cwe": "CWE-798",
        "impact": "Full DB access and arbitrary OS command execution as postgres user.",
        "ranking_reason": "Default credentials never changed, trivially exploitable.",
        "remediation_short": "Change default PostgreSQL credentials immediately.",
        "remediation_package": "postgresql",
        "remediation_cmd": "sudo -u postgres psql -c \"ALTER USER postgres PASSWORD 'strongpassword';\"",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-1999-0502",
        ],
    },
    # ── MySQL default credentials ─────────────────────────────────────
    {
        "match_service": "mysql",
        "match_port": 3306,
        "match_version_contains": None,
        "cve_id": "CVE-1999-0502",
        "cvss_v3": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "critical",
        "description": "MySQL is accessible with default credentials (root with empty password), allowing full database access.",
        "exploit_available": True,
        "msf_module": "auxiliary/scanner/mysql/mysql_login",
        "exploit_complexity": "low",
        "attack_vector": "network",
        "privileges_required": "none",
        "user_interaction": "none",
        "owasp_category": "A07:2021 – Identification and Authentication Failures",
        "cwe": "CWE-798",
        "impact": "Full MySQL root access; can read all databases and potentially write files to disk.",
        "ranking_reason": "Default empty-password root is universally known for Metasploitable.",
        "remediation_short": "Set a strong MySQL root password.",
        "remediation_package": "mysql-server",
        "remediation_cmd": "mysqladmin -u root password 'strongpassword'",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-1999-0502",
        ],
    },
    # ── Apache Tomcat default credentials ────────────────────────────
    {
        "match_service": "http",
        "match_port": 8180,
        "match_version_contains": None,
        "cve_id": "CVE-2009-3843",
        "cvss_v3": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "critical",
        "description": "Apache Tomcat Manager is accessible with default credentials (tomcat:tomcat), allowing WAR file deployment for arbitrary code execution.",
        "exploit_available": True,
        "msf_module": "exploit/multi/http/tomcat_mgr_upload",
        "exploit_complexity": "low",
        "attack_vector": "network",
        "privileges_required": "none",
        "user_interaction": "none",
        "owasp_category": "A07:2021 – Identification and Authentication Failures",
        "cwe": "CWE-798",
        "impact": "Remote code execution as the Tomcat service user via WAR deployment.",
        "ranking_reason": "Default manager credentials allow direct WAR upload and code execution.",
        "remediation_short": "Disable Tomcat manager or change default credentials.",
        "remediation_package": "tomcat",
        "remediation_cmd": "nano /etc/tomcat/tomcat-users.xml  # remove default users",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2009-3843",
        ],
    },
    # ── Druby / DRb ──────────────────────────────────────────────────
    {
        "match_service": "drb",
        "match_port": 8787,
        "match_version_contains": None,
        "cve_id": "CVE-2013-0156",
        "cvss_v3": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "critical",
        "description": "Ruby DRb (druby) allows unauthenticated remote object instantiation, leading to arbitrary code execution on the server.",
        "exploit_available": True,
        "msf_module": "exploit/linux/misc/drb_remote_codeexec",
        "exploit_complexity": "low",
        "attack_vector": "network",
        "privileges_required": "none",
        "user_interaction": "none",
        "owasp_category": "A08:2021 – Software and Data Integrity Failures",
        "cwe": "CWE-502",
        "impact": "Unauthenticated remote code execution as Ruby runtime user via DRb.",
        "ranking_reason": "Exposed DRb service is universally exploitable on Metasploitable.",
        "remediation_short": "Disable DRb service or restrict access.",
        "remediation_package": None,
        "remediation_cmd": "iptables -A INPUT -p tcp --dport 8787 -j DROP",
        "references": [
            "https://www.rapid7.com/db/modules/exploit/linux/misc/drb_remote_codeexec/",
        ],
    },
    # ── Bindshell / Ingreslock backdoor (port 1524) ───────────────────
    {
        "match_service": "ingreslock",
        "match_port": 1524,
        "match_version_contains": None,
        "cve_id": "CVE-1999-0654",
        "cvss_v3": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "severity": "critical",
        "description": "A backdoor root shell is listening on port 1524 (ingreslock). Any TCP connection receives an immediate root shell.",
        "exploit_available": True,
        "msf_module": None,   # direct netcat — no MSF module needed
        "exploit_complexity": "low",
        "attack_vector": "network",
        "privileges_required": "none",
        "user_interaction": "none",
        "owasp_category": "A05:2021 – Security Misconfiguration",
        "cwe": "CWE-912",
        "impact": "Immediate unauthenticated root shell via TCP connection to port 1524.",
        "ranking_reason": "Literal bind shell listening — no exploit needed, just connect.",
        "remediation_short": "Close port 1524 immediately.",
        "remediation_package": None,
        "remediation_cmd": "iptables -A INPUT -p tcp --dport 1524 -j DROP",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-1999-0654",
        ],
    },
    # ── NFS world-readable exports ────────────────────────────────────
    {
        "match_service": "nfs",
        "match_port": 2049,
        "match_version_contains": None,
        "cve_id": "CVE-1999-0170",
        "cvss_v3": 9.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "severity": "critical",
        "description": "NFS exports are world-readable, allowing unauthenticated remote access to filesystem contents.",
        "exploit_available": True,
        "msf_module": None,
        "exploit_complexity": "low",
        "attack_vector": "network",
        "privileges_required": "none",
        "user_interaction": "none",
        "owasp_category": "A05:2021 – Security Misconfiguration",
        "cwe": "CWE-732",
        "impact": "Read/write access to exported filesystem — may include /etc/passwd and SSH keys.",
        "ranking_reason": "World-readable NFS with sensitive data is a critical misconfiguration.",
        "remediation_short": "Restrict NFS exports with proper access controls.",
        "remediation_package": "nfs-kernel-server",
        "remediation_cmd": "nano /etc/exports  # restrict exports to specific IPs",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-1999-0170",
        ],
    },
    # ── Telnet / rlogin unauthenticated ───────────────────────────────
    {
        "match_service": "telnet",
        "match_port": 23,
        "match_version_contains": None,
        "cve_id": "CVE-1999-0619",
        "cvss_v3": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "critical",
        "description": "Telnet service transmits credentials and data in cleartext, enabling credential interception and brute-force attacks.",
        "exploit_available": True,
        "msf_module": "auxiliary/scanner/telnet/telnet_login",
        "exploit_complexity": "low",
        "attack_vector": "network",
        "privileges_required": "none",
        "user_interaction": "none",
        "owasp_category": "A02:2021 – Cryptographic Failures",
        "cwe": "CWE-319",
        "impact": "Credential interception and shell access via cleartext Telnet.",
        "ranking_reason": "Cleartext protocol exposes credentials; default creds allow direct login.",
        "remediation_short": "Disable telnet and use SSH instead.",
        "remediation_package": "telnetd",
        "remediation_cmd": "systemctl disable telnetd && systemctl stop telnetd",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-1999-0619",
        ],
    },
]


def match_kb_findings(service: str, port: Optional[int], version: str) -> list[dict]:
    """
    Return all KB entries that match the given service/port/version from recon.
    Deduplicates by CVE ID so the same CVE isn't returned twice.
    """
    service_lower  = service.lower()
    version_lower  = (version or "").lower()
    matched: dict  = {}   # cve_id → entry (deduplicate)

    for entry in METASPLOITABLE2_KB:
        # Service keyword match
        kw = entry["match_service"].lower()
        if kw not in service_lower:
            continue

        # Port match (None means any port)
        if entry["match_port"] is not None and entry["match_port"] != port:
            continue

        # Version substring match (None means any version)
        vc = entry.get("match_version_contains")
        if vc and vc.lower() not in version_lower:
            continue

        cve = entry["cve_id"]
        if cve not in matched:
            matched[cve] = {k: v for k, v in entry.items()
                            if not k.startswith("match_")}

    return list(matched.values())
