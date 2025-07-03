"""
Hardcoded API Key Test Cases for Bandit Rules
"""

# Test case for B906 - AWS key detection
def test_aws_key_detection():
    # This will trigger B906 rule
    aws_key = "AKIA1234567890123456"
    aws_secret = "AGPA9876543210987654321098765432"

# Test case for B907 - GitHub token detection
def test_github_token_detection():
    # This will trigger B907 rule
    github_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"

# Test case for B908 - OpenAI key detection
def test_openai_key_detection():
    # This will trigger B908 rule
    openai_key = "sk-proj-1234567890abcdefghijklmnopqrstuvwxyz1234567890ab"

# Test case for B909 - Sensitive variable assignment
def test_sensitive_variable_assignment():
    # This will trigger B909 rule
    api_key = "1234567890abcdefghijklmnopqrstuvwxyz"
    secret_key = "0987654321zyxwvutsrqponmlkjihgfedcba"

# Test case for B910 - Auth header detection
def test_auth_header_detection():
    import requests
    # This will trigger B910 rule
    requests.get("https://example.com", 
                 headers={"Authorization": "Bearer 1234567890abcdefghij"})

if __name__ == "__main__":
    test_aws_key_detection()
    test_github_token_detection()
    test_openai_key_detection()
    test_sensitive_variable_assignment()
    test_auth_header_detection()