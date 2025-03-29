"""
This script contains tests for pam_userdb database migration.
"""

import os
import re
import pytest

db_file = "test.gdbm"


def client_version(multihost):
    if int(re.findall(r'\d+', multihost.client[0].distro)[0]) >= 10:
        return True


@pytest.mark.tier1
class TestPamBz(object):
    def test_pam_userdb_auth(self, multihost):
        """
        :title: Try authentication with user from gdbm database
        :id: 6e2bb32a-6e92-11ef-937b-52590940e9ab
        :steps:
            1. Create user password pair in gdbm database
            2. Configure pam files to authenticate with newly created db file
            3. Try to log in with the user password pair
        :expectedresults:
            1. Should succeed
            2. Should succeed
            3. Should succeed
        """
        if not client_version(multihost):
            pytest.skip("Gdbm support is not available, skipping")
        client = multihost.client[0]
        file_location = "/multihost_test/bz_automation/script/pam_userdb.py"
        multihost.client[0].transport.put_file(os.getcwd() +
                                               file_location,
                                               '/tmp/pam_userdb.py')
        gdbm_file = "/etc/security/test_users.gdbm"
        pam_service = "/etc/pam.d/test_pam_userdb"
        # Create user password pair in gdbm database
        command = ['store user1 password1',
                   'store user2 password2',
                   'store user3 password3']
        for comm in command:
            client.run_command(f'echo {comm}| gdbmtool {gdbm_file}')
        # Configure pam files to authenticate with newly created db file
        client.run_command(f'echo "auth required pam_userdb.so db={gdbm_file}" > {pam_service}')
        client.run_command(f'echo "account required pam_permit.so" >> {pam_service}')
        # Try to log in with the user password pair
        finall_result = client.run_command("python /tmp/pam_userdb.py").stdout_text
        for user in ["user1", "user2", "user3"]:
            assert f"Authentication successful for user: {user}" in finall_result
        assert "Authentication failed for user: user4" in finall_result
        client.run_command(f"rm -vf {gdbm_file}")
        client.run_command(f"rm -vf {pam_service}")
        client.run_command(f"rm -vf /tmp/pam_userdb.py")

    def test_userdb_migration(self, multihost):
        """
        :title: Migrate libdb to gdbm
        :id: 745ea324-6e92-11ef-9e65-52590940e9ab
        :steps:
            1. Copy libdb to gdbm converted db file to client machine
            2. Configure pam services to authenticate against preexisting user password from db file
            3. Try to log in with the user
        :expectedresults:
            1. Should succeed
            2. Should succeed
            3. Should succeed
        """
        if not client_version(multihost):
            pytest.skip("Gdbm support is not available, skipping")
        client = multihost.client[0]
        gdbm_file = "/etc/security/test_users.gdbm"
        pam_service = "/etc/pam.d/test_pam_userdb"
        file_location = "/multihost_test/bz_automation/script/pam_userdb.py"
        multihost.client[0].transport.put_file(os.getcwd() +
                                               file_location,
                                               '/tmp/pam_userdb.py')
        # Copy libdb to gdbm converted db file to client machine
        file_location = "/multihost_test/bz_automation/script/test_users.gdbm"
        multihost.client[0].transport.put_file(os.getcwd() +
                                               file_location,
                                               '/tmp/test_users.gdbm')

        client.run_command(f"cp -vf /tmp/test_users.gdbm {gdbm_file}")
        # Configure pam services to authenticate against preexisting user password from db file
        client.run_command(f"echo 'auth         required      pam_userdb.so db={gdbm_file}' > {pam_service}")
        client.run_command(f"echo 'account         required      pam_userdb.so db={gdbm_file}' >> {pam_service}")
        # Try to log in with the user
        finall_result = client.run_command("python /tmp/pam_userdb.py").stdout_text
        for user in ["user1", "user2", "user3"]:
            assert f"Authentication successful for user: {user}" in finall_result
        assert "Authentication failed for user: user4" in finall_result
        client.run_command(f"rm -vf {gdbm_file}")
        client.run_command(f"rm -vf {pam_service}")
        client.run_command(f"rm -vf /tmp/pam_userdb.py")
        client.run_command(f"rm -vf /tmp/test_users.gdbm")
