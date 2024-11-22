"""
PAM Test Cases

:requirement: pam
"""

import pytest
import subprocess
import time
import paramiko
import os
from sssd.testlib.common.utils import SSHClient
from sssd.testlib.common.expect import pexpect_ssh
from sssd.testlib.common.ssh2_python import check_login_client


def execute_cmd(multihost, command):
    cmd = multihost.client[0].run_command(command)
    return cmd


def config_and_login(multihost, config):
    """
    Configure access.conf, check login and restore
    """
    client = multihost.client[0]
    client.run_command(f"echo '{config}' >> /etc/security/access.conf")
    client.run_command("echo '-:ALL:ALL' >> /etc/security/access.conf")
    assert "successfully" in \
           client.run_command("sh /tmp/bz824858.sh local_anuj Secret123",
                              raiseonerr=False).stdout_text
    client.run_command("cp -vf /etc/security/access.conf_anuj /etc/security/access.conf")


@pytest.mark.tier1
class TestPamBz(object):
    def test_read_faillock_conf_option(self, multihost, create_localusers):
        """
        :title: Faillock command does not read faillock.conf option
        :id: df4ef7e0-a754-11ec-8300-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1978029
        """
        execute_cmd(multihost, "yum install policycoreutils-python-utils")
        execute_cmd(multihost, "authselect select sssd --force")
        execute_cmd(multihost, "authselect enable-feature with-faillock")
        if "faillock" not in execute_cmd(multihost, "ls /var/log/").stdout_text:
            execute_cmd(multihost, "mkdir /var/log/faillock")
        multihost.client[0].run_command('semanage fcontext '
                                        '-a -t faillog_t '
                                        '"/var/log/faillock(/.*)?"',
                                        raiseonerr=False)
        execute_cmd(multihost, "restorecon -Rv /var/log/faillock")
        execute_cmd(multihost, "cp -vf /etc/security/faillock.conf "
                               "/etc/security/faillock.conf_bkp")
        execute_cmd(multihost, "echo 'dir = /var/log/faillock' >> "
                               "/etc/security/faillock.conf")
        # Make a wrong password attempt to generate logs
        with pytest.raises(paramiko.ssh_exception.AuthenticationException):
            SSHClient(multihost.client[0].ip, username="local_anuj",
                      password="bad_pass")
        # Tests faillock with prefix --user
        assert 'V' in execute_cmd(multihost, "faillock --user local_anuj").stdout_text.split('\n')[2]
        # check --reset command without directory
        execute_cmd(multihost, "faillock --user local_anuj --reset")
        # check above command worked
        assert 'V' not in execute_cmd(multihost, "faillock --user local_anuj").stdout_text.split('\n')[2]
        # Make a wrong password attempt to generate logs after reset
        with pytest.raises(paramiko.ssh_exception.AuthenticationException):
            SSHClient(multihost.client[0].ip, username="local_anuj",
                      password="bad_pass")
        # Tests faillock with prefix --dir and --user
        assert 'V' in execute_cmd(multihost, "faillock --dir "
                                             "/var/log/faillock "
                                             "--user local_anuj").stdout_text.split('\n')[2]
        # check --reset command with directory along with other prefixes
        execute_cmd(multihost, "faillock --dir "
                               "/var/log/faillock "
                               "--user local_anuj --reset")
        # check if command works again after reset
        assert 'V' not in execute_cmd(multihost, "faillock --dir "
                                             "/var/log/faillock "
                                             "--user local_anuj").stdout_text.split('\n')[2]
        # Just cleaning and restoring
        execute_cmd(multihost, "faillock --dir "
                               "/var/log/faillock --user "
                               "local_anuj --reset")
        execute_cmd(multihost, "cp -vf /etc/security/faillock.conf_bkp "
                               "/etc/security/faillock.conf")

    def test_cve_2010_3316(self, multihost, bkp_pam_config, compile_myxauth):
        """
        :title: CVE-2010-3316-pam_xauth-missing-return-value-checks-from-setuid
        :id: aebe751c-31b8-11ed-a91f-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=637898
        """
        TUSER = "pam-xauth-tester"
        SLOG = "/var/log/secure"
        execute_cmd(multihost, '> /tmp/xauthlog')
        execute_cmd(multihost, f"useradd {TUSER}")
        execute_cmd(multihost, "cp -f myxauth /myxauth")
        execute_cmd(multihost, 'sed -i "s/pam_xauth\.so/pam_xauth\.so '
                               'debug xauthpath=\/myxauth/g" /etc/pam.d/su')
        execute_cmd(multihost, 'echo "pam-xauth-tester    hard    nproc   '
                               '0" >> /etc/security/limits.conf')
        execute_cmd(multihost, 'mkdir -p /root/.xauth')
        execute_cmd(multihost, "echo '*' >> /root/.xauth/export")
        execute_cmd(multihost, f"id -u {TUSER}")
        with pytest.raises(subprocess.CalledProcessError):
            execute_cmd(multihost, f"DISPLAY=0:0 su - {TUSER} -c exit")
        time.sleep(3)
        execute_cmd(multihost, f"tail -n 11 {SLOG} | tee mktemp")
        for i in ["/tmp/myxauth.c", "myxauth"]:
            execute_cmd(multihost, f"rm -vf {i}")
        execute_cmd(multihost, 'rm -vfr /root/.xauth')
        execute_cmd(multihost, f"userdel -rf {TUSER}")
        assert int(execute_cmd(multihost, "cat /tmp/xauthlog | wc -l" ).stdout_text.split()[0]) >= 2

    def test_2082442(self, multihost, bkp_pam_config, create_localusers):
        """
        :title: pam_faillock prints "Consecutive login failures
         for user root account temporarily locked" without even_deny_root
        :id: c1802552-5151-11ed-b8c2-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=2126648
                   https://bugzilla.redhat.com/show_bug.cgi?id=2082442
        """
        execute_cmd(multihost, "> /var/log/secure")
        ssh1 = SSHClient(multihost.client[0].ip, username="local_anuj", password="password123")
        for i in range(4):
            (result, result1, exit_status) = ssh1.execute_cmd('su -', stdin="password1234")
            assert "Password: su: Authentication failure" in result1.readlines()[0]
        assert "Consecutive login failures for user root account temporarily locked" \
               not in execute_cmd(multihost, "cat /var/log/secure").stdout_text

    def test_2091062(self, multihost, create_localusers):
        """
        :title: "error scanning directory" errors from pam_motd
        :id: 556ae15e-560b-11ed-850a-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=2091062
        """
        execute_cmd(multihost, "> /var/log/secure")
        for dirc in ['/run/motd.d', '/etc/motd.d', '/usr/lib/motd.d']:
            execute_cmd(multihost, f"rm -vfr {dirc}")
        client = pexpect_ssh(multihost.client[0].sys_hostname,
                             "local_anuj", 'password123', debug=False)
        client.login(login_timeout=30, sync_multiplier=5, auto_prompt_reset=False)
        client.logout()
        assert "pam_motd: error scanning directory" not in \
               execute_cmd(multihost, "cat /var/log/secure").stdout_text

    def test_pam_faillock_audit(self, multihost, create_localusers, bkp_pam_config):
        """
        :title: Pam_faillock audit events duplicate uid.
        :id: c62fda84-401b-11ee-90bd-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=2231556
        :setup:
            1. Enable pam_faillock in the PAM stack
            2. Modify pam_faillock "deny" option in faillock.conf to
                lock the user at the first attempt (deny=1)
        :steps:
            1. Authenticate as user and input an incorrect password
            2. Check that audit file contains the correct format.
        :expectedresults:
            1. Authentication should fail.
            2. Pam_faillock audit must display messages with the correct format:
                op=pam_faillock suid=UID. Where UID is the ID of the user trying to authenticate.
        """
        client = multihost.client[0]
        execute_cmd(multihost, "authselect select sssd --force")
        execute_cmd(multihost, "authselect enable-feature with-faillock")
        file_location = "/multihost_test/bz_automation/script/wrong_pass.sh"
        multihost.client[0].transport.put_file(os.getcwd() +
                                               file_location,
                                               '/tmp/wrong_pass.sh')
        uid = client.run_command("id -u local_anuj").stdout_text.split()[0]
        client.run_command("cp -vf /etc/security/faillock.conf /etc/security/faillock.conf_anuj")
        client.run_command("echo 'deny = 1' >> /etc/security/faillock.conf")
        client.run_command("> /var/log/audit/audit.log")
        client.run_command("sh /tmp/wrong_pass.sh", raiseonerr=False)
        time.sleep(3)
        log_str = multihost.client[0].get_file_contents("/var/log/audit/audit.log").decode('utf-8')
        client.run_command("cp -vf /etc/security/faillock.conf_anuj /etc/security/faillock.conf")
        assert f'op=pam_faillock suid={uid}' in log_str

    def test_2228934(self, multihost, create_localusers, bkp_pam_config):
        """
        :title: Using "pam_access", ssh login fails with this entry in
            /etc/security/access.conf "+:username:localhost server1.example.com"
        :id: 5b669434-35b9-11ee-b8b3-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=2228934
        :steps:
            1. Enable "with-pamaccess" feature using authselect
            2. Configure  /etc/security/access.conf
            3. Try to log in with the user
        :expectedresults:
            1. Should succeed
            2. Should succeed
            3. Should succeed
        """
        client = multihost.client[0]
        file_location = "/multihost_test/bz_automation/script/bz824858.sh"
        multihost.client[0].transport.put_file(os.getcwd() + file_location, '/tmp/bz824858.sh')
        client.run_command("authselect select sssd --force")
        client.run_command("authselect enable-feature with-pamaccess")
        assert "with-pamaccess" in client.run_command("authselect current").stdout_text
        for conf in [
            '+:local_anuj:localhost',
            '+:local_anuj: ::1',
            '+:local_anuj:127.0.0.1',
            '+:local_anuj:127.0.0.1 ::1',
            f'+:local_anuj:127.0.0.1 ::1 {client.sys_hostname}',
            f'+:local_anuj:127.0.0.1 ::1 {client.ip}'
        ]:
            config_and_login(multihost, conf)

    def test_21244(self, multihost, create_localusers, bkp_pam_config):
        """
        :title: CVE-2024-22365 pam: allowing unpriledged user to block another user namespace
        :id: f9e4f9b8-c57c-11ee-aa1d-845cf3eff344
        :bugzilla: https://issues.redhat.com/browse/RHEL-21242
                   https://issues.redhat.com/browse/RHEL-21244
        :steps:
            1. Change namespace.conf
            2. Change password-auth
            3. An unprivileged user can now place a FIFO at $HOME/tmp
            4. Try to log in as this user with `pam_namespace` configured
        :expectedresults:
            1. $HOME/tmp /var/tmp/tmp-inst/ user:create root
            2. session required pam_namespace.so
            3. nobody$ mkfifo $HOME/tmp
            4. Should not cause a local denial of service
        """
        client = multihost.client[0]
        file_location = "/multihost_test/bz_automation/script/authentication.sh"
        client.run_command("setenforce 0")
        multihost.client[0].transport.put_file(os.getcwd() + file_location, '/tmp/authentication.sh')
        client.run_command("echo '$HOME/tmp /var/tmp/tmp-inst/ user:create root' >> /etc/security/namespace.conf")
        execute_cmd(multihost, "echo 'session required pam_namespace.so' >> /etc/pam.d/password-auth")
        client.run_command("runuser -l  local_anuj -c 'mkfifo $HOME/tmp'")
        with pytest.raises(Exception):
            client.run_command("sh /tmp/authentication.sh")
        client.run_command("rm -vf /tmp/authentication.sh")

    def test_libpam_raise_line_buffer_size_limit(self, multihost, create_localusers, bkp_pam_config):
        """
        :title: libpam rejects pam config files containing long lines
        :id: c9dbce70-2d4d-11ef-b036-845cf3eff344
        :bugzilla: https://issues.redhat.com/browse/RHEL-5051
                   https://issues.redhat.com/browse/RHEL-40705
        :steps:
            1. Edit /etc/pam.d/system-auth file to add pam_tty_audit.so with options "disable=* enable=".
                Make the user list under "enable" longer than 1024 characters.
            2. Try Login using command which uses "/etc/pam.d/system-auth" file. Example su - <username>
        :expectedresults:
            1. Edit should be successfull.
            2. Successful login.
        """
        client = multihost.client[0]
        client.run_command("echo 'session    required     pam_tty_audit.so disable=* enable=local_anuj0,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX,local_anujX' >> /etc/pam.d/system-auth")
        client.run_command("su - local_anuj -c exit")

    def test_pam_access(self, multihost, create_localusers, bkp_pam_config):
        """
        :title: Using "pam_access", ssh login fails with this entry in
                /etc/security/access.conf "+:username:127.0.0.1"
        :id: d2a52d84-9fe0-11ef-a76a-3c18a0580700
        :bugzilla: https://issues.redhat.com/browse/RHEL-65223
        :setup:
            1. Copy authentication script to client machine
            2. Enable "with-pamaccess" feature using authselect
            3. Configure  /etc/security/access.conf
        :steps:
            1. Try to log in with the user
        :expectedresults:
            1. Should succeed
        """
        client = multihost.client[0]
        file_location = "/multihost_test/bz_automation/script/authentication.sh"
        multihost.client[0].transport.put_file(os.getcwd() + file_location, '/tmp/authentication.sh')
        client.run_command("authselect select sssd --force")
        client.run_command("authselect enable-feature with-pamaccess")
        assert "with-pamaccess" in client.run_command("authselect current").stdout_text
        client.run_command(f"echo '+:local_anuj:127.0.0.1' >> /etc/security/access.conf")
        client.run_command("echo '-:ALL:ALL' >> /etc/security/access.conf")
        client.run_command("sh /tmp/authentication.sh")

    def test_pam_access_account(self, multihost, create_localusers, bkp_pam_config):
        """
        :title: pam_access(sshd:account): cannot resolve hostname "LOCAL"
                after upgrading to pam-1.5.1-19
        :id: fcbae668-9fe0-11ef-9fbb-3c18a0580700
        :bugzilla: https://issues.redhat.com/browse/RHEL-39943
        :setup:
            1. Copy authentication script to client machine
            2. Enable "with-pamaccess" feature using authselect
            3. Configure  /etc/security/access.conf
        :steps:
            1. Log in and Check error message does not appear in /var/log/secure
        :expectedresults:
            1. Should succeed
        """
        client = multihost.client[0]
        client.run_command("> /var/log/secure")
        file_location = "/multihost_test/bz_automation/script/authentication.sh"
        multihost.client[0].transport.put_file(os.getcwd() + file_location, '/tmp/authentication.sh')
        client.run_command("authselect select sssd --force")
        client.run_command("authselect enable-feature with-pamaccess")
        assert "with-pamaccess" in client.run_command("authselect current").stdout_text
        client.run_command(f"echo '-:local_anuj:LOCAL' >> /etc/security/access.conf")
        client.run_command("echo '+:local_anuj:ALL' >> /etc/security/access.conf")
        client.run_command("sh /tmp/authentication.sh")
        log_str = multihost.client[0].get_file_contents("/var/log/secure").decode('utf-8')
        assert "LOCAL" not in log_str

    def test_cve_access_control_bypass(self, multihost, bkp_pam_config, create_localusers):
        """
        :title: Improper hostname interpretation in pam_access leads to access control bypass
        :id: ade05f56-a818-11ef-b978-52590940e9ab
        :bugzilla: https://issues.redhat.com/browse/RHEL-66241
        :setup:
            1. Ensure pam_access is configured in /etc/pam.d/sshd
            2. Configure /etc/security/access.conf
            3. On a second system, spoof the hostname to match one of the tokens
        :steps:
            1. Initiate an ssh connection
        :expectedresults:
            1. Should not succeed
        """
        client = multihost.client[0]
        file_location = "/multihost_test/bz_automation/script/authentication_master.sh"
        multihost.master[0].transport.put_file(os.getcwd() + file_location, '/tmp/authentication_master.sh')

        client.run_command("authselect enable-feature with-pamaccess")
        execute_cmd(multihost, 'echo "+:local_anuj:cron crond tty1 tty2 tty3" >> /etc/security/access.conf')
        execute_cmd(multihost, 'echo "-:local_anuj:ALL" >> /etc/security/access.conf')

        multihost.master[0].run_command("hostnamectl set-hostname crond")
        result = multihost.master[0].run_command(f"sh /tmp/authentication_master.sh "
                                                 f"{multihost.client[0].sys_hostname}").stdout_text
        assert "Connection closed by" in result
