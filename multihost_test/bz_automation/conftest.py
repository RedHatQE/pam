"""conftest.py for pam"""

from __future__ import print_function
import subprocess
import pytest
import time
import ldap
import posixpath
import os
import random
from pytest_multihost import make_multihost_fixture
from sssd.testlib.common.qe_class import session_multihost
from sssd.testlib.common.paths import SSSD_DEFAULT_CONF
from sssd.testlib.common.utils import PkiTools, sssdTools, LdapOperations
from sssd.testlib.common.libdirsrv import DirSrvWrap
from sssd.testlib.common.exceptions import PkiLibException, LdapException
from sssd.testlib.common.libkrb5 import krb5srv


def pytest_configure():
    """ Namespace hook to add below dict in the pytest namespace """
    pytest.num_masters = 0
    pytest.num_ad = 0
    pytest.num_atomic = 0
    pytest.num_replicas = 0
    pytest.num_clients = 1
    pytest.num_others = 0


def execute_cmd(session_multihost, command):
    cmd = session_multihost.client[0].run_command(command)
    return cmd


@pytest.fixture(scope="class")
def multihost(session_multihost, request):
    """ Multihost fixture to be used by tests """
    if hasattr(request.cls(), 'class_setup'):
        request.cls().class_setup(session_multihost)
        request.addfinalizer(
            lambda: request.cls().class_teardown(session_multihost))
    return session_multihost


@pytest.fixture(scope='function')
def backupsssdconf(session_multihost, request):
    """ Backup and restore sssd.conf """
    bkup = 'cp -f %s %s.orig' % (SSSD_DEFAULT_CONF,
                                 SSSD_DEFAULT_CONF)
    session_multihost.client[0].run_command(bkup)
    session_multihost.client[0].service_sssd('stop')

    def restoresssdconf():
        """ Restore sssd.conf """
        restore = 'cp -f %s.orig %s' % (SSSD_DEFAULT_CONF, SSSD_DEFAULT_CONF)
        session_multihost.client[0].run_command(restore)
    request.addfinalizer(restoresssdconf)


@pytest.fixture(scope='function')
def bkp_pam_config(session_multihost, request):
    """ create users for test """
    for bkp in ['/etc/pam.d/system-auth',
                '/etc/security/pwhistory.conf',
                '/etc/security/opasswd',
                '/etc/bashrc',
                '/etc/pam.d/su',
                '/etc/pam.d/su-l',
                '/etc/security/access.conf',
                '/etc/pam.d/sshd',
                '/etc/pam.d/password-auth',
                '/etc/security/limits.conf',
                '/etc/security/namespace.conf']:
        execute_cmd(session_multihost, f"cp -vf {bkp} {bkp}_anuj")

    def restoresssdconf():
        """ Restore """
        for bkp in ['/etc/pam.d/system-auth',
                    '/etc/security/pwhistory.conf',
                    '/etc/security/opasswd',
                    '/etc/bashrc',
                    '/etc/pam.d/su',
                    '/etc/pam.d/su-l',
                    '/etc/security/access.conf',
                    '/etc/pam.d/sshd',
                    '/etc/pam.d/password-auth',
                    '/etc/security/limits.conf',
                    '/etc/security/namespace.conf']:
            execute_cmd(session_multihost, f"mv -vf {bkp}_anuj {bkp}")

    request.addfinalizer(restoresssdconf)


@pytest.fixture(scope='function')
def create_localusers(session_multihost, request):
    """ create users for test """
    execute_cmd(session_multihost, "useradd local_anuj")
    execute_cmd(session_multihost, f"echo password123 | passwd --stdin local_anuj")
    execute_cmd(session_multihost, "useradd pamtest1")
    execute_cmd(session_multihost, "groupadd testgroup")

    def restoresssdconf():
        """ Restore """
        execute_cmd(session_multihost, "userdel -rf local_anuj")
        execute_cmd(session_multihost, "userdel -rf pamtest1")
        execute_cmd(session_multihost, "groupdel testgroup")

    request.addfinalizer(restoresssdconf)


@pytest.fixture(scope='class')
def unlimited_ssh(session_multihost, request):
    """ create users for test """
    execute_cmd(session_multihost, "cp -vf /etc/security/limits.conf /tmp/limits.conf_anuj")
    user = "anuj_test"
    execute_cmd(session_multihost, "yum update -y pam")
    execute_cmd(session_multihost, "useradd anuj_test")
    execute_cmd(session_multihost, f"echo password123 | passwd --stdin {user}")
    execute_cmd(session_multihost, 'echo "anuj_test hard nofile -1" >> "/etc/security/limits.conf"')

    def restore_conf():
        """ Restore """
        execute_cmd(session_multihost, "cp -vf /tmp/limits.conf_anuj /etc/security/limits.conf")
        execute_cmd(session_multihost, "userdel -rf anuj_test")

    request.addfinalizer(restore_conf)


@pytest.fixture(scope='function')
def create_system_user(session_multihost, request):
    """ create users for test """
    execute_cmd(session_multihost, "useradd -u 101 systest")

    def restore_conf():
        """ Restore """
        execute_cmd(session_multihost, "userdel -rf systest")

    request.addfinalizer(restore_conf)


@pytest.fixture(scope='function')
def compile_myxauth(session_multihost, request):
    """ Compile myxauth.c """
    file_location1 = "/multihost_test/bz_automation/script/myxauth.c"
    session_multihost.client[0].transport.put_file(os.getcwd() +
                                           file_location1,
                                           '/tmp/myxauth.c')
    execute_cmd(session_multihost, "gcc /tmp/myxauth.c -o myxauth")


@pytest.fixture(scope="session", autouse=True)
def setup_session(session_multihost, request):
    """
    Session fixture which calls fixture in order before tests run
    :param obj session_multihost: multihost object
    :param obj request: pytest request object
    """
    execute_cmd(session_multihost, "yum update -y pam")
    execute_cmd(session_multihost, "yum install -y gcc pam-devel")

