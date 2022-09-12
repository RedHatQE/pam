# Configuration file for multihost tests.

# Load additional plugins
from __future__ import annotations
import pytest
from lib.multihost import KnownTopology
from lib.multihost import Multihost, Topology, TopologyDomain
from lib.multihost.roles import Client


@pytest.mark.topology(KnownTopology.Client)
def execute_cmd(client: Client, command):
    """ Execute command on client """
    cmd = client.host.exec(command)
    return cmd


pytest_plugins = (
    'lib.multihost.plugin',
)


@pytest.fixture(scope='function')
def bkp_pam_config(mh: Multihost, request):
    """ create users for test """
    client: Client = mh.sssd.client[0]
    for bkp in ['/etc/pam.d/system-auth',
                '/etc/security/opasswd',
                '/etc/bashrc',
                '/etc/pam.d/su',
                '/etc/pam.d/su-l',
                '/etc/security/access.conf',
                '/etc/pam.d/sshd',
                '/etc/pam.d/password-auth',
                '/etc/security/limits.conf']:
        execute_cmd(client, f"cp -vf {bkp} {bkp}_anuj")

    def restoresssdconf():
        """ Restore """
        for bkp in ['/etc/pam.d/system-auth',
                    '/etc/security/opasswd',
                    '/etc/bashrc',
                    '/etc/pam.d/su',
                    '/etc/pam.d/su-l',
                    '/etc/security/access.conf',
                    '/etc/pam.d/sshd',
                    '/etc/pam.d/password-auth',
                    '/etc/security/limits.conf']:
            execute_cmd(client, f"mv -vf {bkp}_anuj {bkp}")

    request.addfinalizer(restoresssdconf)


@pytest.fixture(scope='function')
def create_localusers(mh: Multihost, request):
    """ create users for test """
    client: Client = mh.sssd.client[0]
    execute_cmd(client, "useradd local_anuj")
    execute_cmd(client, f"echo password123 | passwd --stdin local_anuj")
    execute_cmd(client, "useradd pamtest1")
    execute_cmd(client, "groupadd testgroup")

    def restoresssdconf():
        """ Restore """
        execute_cmd(client, "userdel -rf local_anuj")
        execute_cmd(client, "userdel -rf pamtest1")
        execute_cmd(client, "groupdel testgroup")

    request.addfinalizer(restoresssdconf)
