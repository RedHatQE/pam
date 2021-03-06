
import pytest
import subprocess
import os
import time
import paramiko
from sssd.testlib.common.utils import SSHClient


def execute_cmd(multihost, command):
    cmd = multihost.client[0].run_command(command)
    return cmd


@pytest.mark.tier1
class TestPamBz(object):
    def test_read_faillock_conf_option(self, multihost, create_localusers):
        """
        :title: Faillock command does not read faillock.conf option
        :id: df4ef7e0-a754-11ec-8300-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1978029
        """
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
