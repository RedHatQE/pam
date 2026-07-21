"""
CVE-2026-54411: pam_userdb password comparison timing leak

:requirement: pam
:casecomponent: pam
:subsystemteam: sst_idm_sssd
:status: approved
"""

import json
import os
import re
import pytest


def client_version(multihost):
    """Return major RHEL/CentOS version as int."""
    return int(re.findall(r'\d+', multihost.client[0].distro)[0])


def is_gdbm(multihost):
    """c10s+ uses gdbm, c9s uses libdb."""
    return client_version(multihost) >= 10


def create_db_gdbm(client, db_path, entries):
    """Create a gdbm database with user/password pairs."""
    for user, password in entries:
        client.run_command(
            f'echo "store {user} {password}" | gdbmtool {db_path}')


def create_db_libdb(client, db_path, entries):
    """Create a BerkeleyDB hash database with user/password pairs."""
    lines = ""
    for user, password in entries:
        lines += f"{user}\\n{password}\\n"
    client.run_command(
        f'printf "{lines}" | db_load -T -t hash {db_path}')


def create_db(client, db_path, entries, use_gdbm):
    """Create userdb database using the appropriate backend."""
    if use_gdbm:
        create_db_gdbm(client, db_path, entries)
    else:
        create_db_libdb(client, db_path, entries)


def setup_pam_service(client, service_path, db_path, extra_args=""):
    """Configure a PAM service file for pam_userdb."""
    args = f"db={db_path} crypt=none"
    if extra_args:
        args += f" {extra_args}"
    client.run_command(
        f'echo "auth required pam_userdb.so {args}" > {service_path}')
    client.run_command(
        f'echo "account required pam_permit.so" >> {service_path}')


@pytest.mark.tier1
class TestCVE202654411(object):
    """Tests for CVE-2026-54411: pam_userdb timing leak fix."""

    def test_pam_userdb_functional(self, multihost):
        """
        :title: pam_userdb basic authentication works after timing leak fix
        :id: a1b2c3d4-1111-2222-3333-444455556666
        :bugzilla:  https://redhat.atlassian.net/browse/RHEL-191705
                    https://redhat.atlassian.net/browse/RHEL-191706
                    https://redhat.atlassian.net/browse/RHEL-191704
                    https://redhat.atlassian.net/browse/RHEL-191703
                    https://redhat.atlassian.net/browse/RHEL-191702
                    https://redhat.atlassian.net/browse/RHEL-191701
                    https://redhat.atlassian.net/browse/RHEL-191700
                    https://redhat.atlassian.net/browse/RHEL-191699
                    https://redhat.atlassian.net/browse/RHEL-191698
                    https://redhat.atlassian.net/browse/RHEL-191697
                    https://redhat.atlassian.net/browse/RHEL-191696
                    https://redhat.atlassian.net/browse/RHEL-191695
                    https://redhat.atlassian.net/browse/RHEL-191694
        :steps:
            1. Create userdb database with known user/password pairs
            2. Configure PAM service with pam_userdb crypt=none
            3. Authenticate with correct credentials
            4. Authenticate with wrong password
            5. Authenticate with unknown user
        :expectedresults:
            1. Should succeed
            2. Should succeed
            3. Should succeed (PAM_SUCCESS)
            4. Should fail (PAM_AUTH_ERR)
            5. Should fail (PAM_AUTH_ERR)
        """
        client = multihost.client[0]
        use_gdbm = is_gdbm(multihost)
        db_ext = ".gdbm" if use_gdbm else ".db"
        db_path = f"/etc/security/cve_test_users{db_ext}"
        pam_service = "/etc/pam.d/test_pam_userdb_cve"
        helper_script = "/tmp/pam_userdb_timing.py"
        file_location = "/multihost_test/bz_automation/script/pam_userdb_timing.py"

        try:
            client.transport.put_file(
                os.getcwd() + file_location, helper_script)

            entries = [("user1", "password1"),
                       ("user2", "password2"),
                       ("user3", "longpassword123")]
            create_db(client, db_path, entries, use_gdbm)
            setup_pam_service(client, pam_service, db_path)

            output = client.run_command(
                f"python3 {helper_script}").stdout_text
            results = json.loads(output)

            assert results["functional"]["correct_auth"], \
                "Correct credentials should authenticate"
            assert results["functional"]["wrong_pass"], \
                "Wrong password should be rejected"
            assert results["functional"]["wrong_user"], \
                "Unknown user should be rejected"
        finally:
            client.run_command(f"rm -f {db_path}", raiseonerr=False)
            client.run_command(f"rm -f {pam_service}", raiseonerr=False)
            client.run_command(f"rm -f {helper_script}", raiseonerr=False)

    def test_pam_userdb_icase_functional(self, multihost):
        """
        :title: pam_userdb icase option works correctly after timing fix
        :id: d4e5f6a7-4444-5555-6666-777788889999
        :bugzilla:  https://redhat.atlassian.net/browse/RHEL-191705
                    https://redhat.atlassian.net/browse/RHEL-191706
                    https://redhat.atlassian.net/browse/RHEL-191704
                    https://redhat.atlassian.net/browse/RHEL-191703
                    https://redhat.atlassian.net/browse/RHEL-191702
                    https://redhat.atlassian.net/browse/RHEL-191701
                    https://redhat.atlassian.net/browse/RHEL-191700
                    https://redhat.atlassian.net/browse/RHEL-191699
                    https://redhat.atlassian.net/browse/RHEL-191698
                    https://redhat.atlassian.net/browse/RHEL-191697
                    https://redhat.atlassian.net/browse/RHEL-191696
                    https://redhat.atlassian.net/browse/RHEL-191695
                    https://redhat.atlassian.net/browse/RHEL-191694
        :steps:
            1. Create userdb database with a known password
            2. Configure PAM service with pam_userdb crypt=none icase
            3. Authenticate with password in different cases
        :expectedresults:
            1. Should succeed
            2. Should succeed
            3. Case-insensitive match should succeed,
               completely wrong password should fail
        """
        client = multihost.client[0]
        use_gdbm = is_gdbm(multihost)
        db_ext = ".gdbm" if use_gdbm else ".db"
        db_path = f"/etc/security/cve_icase{db_ext}"
        pam_service = "/etc/pam.d/test_pam_userdb_icase"

        helper_script = "/tmp/pam_userdb_icase.py"
        file_location = "/multihost_test/bz_automation/script/pam_userdb_icase.py"

        try:
            entries = [("user1", "Password1")]
            create_db(client, db_path, entries, use_gdbm)
            setup_pam_service(client, pam_service, db_path, "icase")

            client.transport.put_file(
                os.getcwd() + file_location, helper_script)
            output = client.run_command(
                f"python3 {helper_script}").stdout_text
            results = json.loads(output)

            assert results["exact"], "Exact match should succeed"
            assert results["lower"], \
                "Case-insensitive match (lowercase) should succeed"
            assert results["upper"], \
                "Case-insensitive match (uppercase) should succeed"
            assert not results["wrong"], "Wrong password should fail"
        finally:
            client.run_command(f"rm -f {db_path}", raiseonerr=False)
            client.run_command(f"rm -f {pam_service}", raiseonerr=False)
            client.run_command(f"rm -f {helper_script}", raiseonerr=False)
