"""
Authentication Bypass Test Cases for Bandit Rules
"""

# Test case for B701 - Hardcoded Credentials
def test_hardcoded_credentials():
    # This will trigger B701 rule
    password = "secret_password"
    api_key = "12345-67890-abcde"
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

# Test case for B702 - Insecure JWT Usage
def test_insecure_jwt_usage():
    import jwt
    # This will trigger B702 rule
    decoded = jwt.decode("token", "secret", verify=False)

# Test case for B703 - Session Authentication Bypass
def test_session_auth_bypass():
    from flask import session
    # This will trigger B703 rule
    session['authenticated'] = True

# Test case for B704 - Missing Authentication Decorator
def admin_dashboard():
    # This will trigger B704 rule
    return "Admin Dashboard"

if __name__ == "__main__":
    test_hardcoded_credentials()
    test_insecure_jwt_usage()
    test_session_auth_bypass()
    admin_dashboard()