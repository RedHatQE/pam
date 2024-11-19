"""
Authentication using PAM
"""
import pam


# Function to simulate authentication using PAM
def authenticate(user, password):
    p = pam.pam()
    # Use python-pam module to perform authentication
    auth = p.authenticate(user, password, service='test_pam_userdb')
    if auth:
        print(f"Authentication successful for user: {user}")
    else:
        print(f"Authentication failed for user: {user}")


# Test cases
authenticate("user1", "password1")
authenticate("user2", "password2")
authenticate("user3", "password3")
authenticate("user4", "password4")  # This should fail
