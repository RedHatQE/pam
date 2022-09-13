import pytest
import os
import subprocess
from lib.multihost import KnownTopology
from lib.multihost.roles import Client


def execute_cmd(client: Client, command):
    """ Execute command on client """
    cmd = client.host.exec(command)
    return cmd


@pytest.mark.topology(KnownTopology.Client)
def test_pwhistory_enforces_root(client: Client, bkp_pam_config, create_localusers):
    """
    :title: bz824858-pam-pwhistory-enforces-root-to-password-change
    :id: a87eb61c-334d-11ed-a639-845cf3eff344
    """
    _PASSWORD = "01_pass_change_01"
    _PASSWORD2 = "02_change_pass_02"
    _PASSWORD3 = "03_aother_pass_03"
    _PASSWORD4 = "04_yet_new_pass_04"
    execute_cmd(client, "cat /etc/pam.d/system-auth > /tmp/system-auth")
    execute_cmd(client, "rm -f /etc/security/opasswd")
    execute_cmd(client, "touch /etc/security/opasswd")
    execute_cmd(client, "chown root:root /etc/security/opasswd")
    execute_cmd(client, "chmod 600 /etc/security/opasswd")
    execute_cmd(client, "echo R3dh4T1nC | passwd --stdin pamtest1")
    execute_cmd(client, "> /etc/security/opasswd")
    execute_cmd(client, "sed -i -e "
                        "'s/^password\s\+sufficient\s\+pam_unix.so/password    "
                        "requisite     pam_pwhistory.so remember=3 use_authtok "
                        "enforce_for_root\\n\\0/'  /etc/pam.d/system-auth")
    file_localtion  = "/multihost_test/bz_automation/test_new_repo/script/bz824858.sh"
    client.host.host.transport.put_file(os.getcwd() +
                                        file_localtion,
                                        '/tmp/bz824858.sh')
    for i in [_PASSWORD, _PASSWORD2, _PASSWORD3]:
        execute_cmd(client, f"sh /tmp/bz824858.sh pamtest1 {i}")
    with pytest.raises(subprocess.CalledProcessError):
        execute_cmd(client, f"sh /tmp/bz824858.sh pamtest1 {_PASSWORD}")
    execute_cmd(client, "echo R3dh4T1nC | passwd --stdin pamtest1")
    execute_cmd(client, "> /etc/security/opasswd")
    execute_cmd(client, "cat /tmp/system-auth > /etc/pam.d/system-auth")
    execute_cmd(client, "sed -i -e 's/^password\s\+sufficient\s\+pam_unix.so/password    "
                        "requisite     pam_pwhistory.so remember=3 use_authtok\\n\\0/'  "
                        "/etc/pam.d/system-auth")
    for i in [_PASSWORD, _PASSWORD2, _PASSWORD3, _PASSWORD4, _PASSWORD]:
        execute_cmd(client, f"sh /tmp/bz824858.sh pamtest1 {i}")
