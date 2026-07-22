"""CVE-2026-54411: Verify pam_userdb functional authentication with crypt=none."""
import pam
import json

SERVICE = "test_pam_userdb_cve"

p = pam.pam()
results = {
    "functional": {
        "correct_auth": p.authenticate("user1", "password1", service=SERVICE),
        "wrong_pass": not p.authenticate("user1", "wrongpass", service=SERVICE),
        "wrong_user": not p.authenticate("nouser", "password1", service=SERVICE),
    }
}

print(json.dumps(results))
