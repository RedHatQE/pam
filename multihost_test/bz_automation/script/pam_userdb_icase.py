"""CVE-2026-54411: Test pam_userdb icase option."""
import pam
import json

p = pam.pam()
service = "test_pam_userdb_icase"
results = {
    "exact": p.authenticate("user1", "Password1", service=service),
    "lower": p.authenticate("user1", "password1", service=service),
    "upper": p.authenticate("user1", "PASSWORD1", service=service),
    "wrong": p.authenticate("user1", "wrongpass", service=service),
}

print(json.dumps(results))
