"""
Test cases for rug_pull.py rules
"""

# B921: Malicious service termination
def test_malicious_service_termination():
    # Simple exit call without args
    exit()
    
    # Exit call with empty args
    exit(*())

# B922: Resource withdrawal
def test_resource_withdrawal():
    import os, shutil
    
    # Dangerous file operations
    os.remove("important_file.txt")
    shutil.rmtree("critical_directory")
    os.unlink("sensitive_data.db")

# B923: Trust violation
def test_trust_violation():
    # Eval with shutdown command
    eval("shutdown()")
    
    # Eval with terminate command
    eval("terminate()")
    
    # Eval with hidden termination
    eval("system.shutdown()")

if __name__ == "__main__":
    test_malicious_service_termination()
    test_resource_withdrawal()
    test_trust_violation()