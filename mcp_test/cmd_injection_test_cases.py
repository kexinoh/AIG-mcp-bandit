"""
Command Injection Test Cases for Bandit Rules
"""

# Test case for B601 - os.system() usage
def test_os_system_usage():
    import os
    # This will trigger B601 rule
    os.system("echo Hello World")

# Test case for B602 - subprocess with shell=True
def test_subprocess_shell_true():
    import subprocess
    # This will trigger B602 rule
    subprocess.run("echo Hello World", shell=True)

# Test case for B603 - eval/exec usage
def test_eval_exec_usage():
    # This will trigger B603 rule
    eval("print('Hello World')")
    exec("print('Hello Again')")

# Test case for B604 - template injection
def test_template_injection():
    from flask import Flask
    app = Flask(__name__)
    # This will trigger B604 rule
    app.jinja_env.from_string("{{ config.items() }}")

# Test case for B605 - command injection through concatenation
def test_command_injection_concatenation():
    import os
    user_input = "malicious_command"
    # This will trigger B605 rule
    os.system("echo " + user_input)

if __name__ == "__main__":
    test_os_system_usage()
    test_subprocess_shell_true()
    test_eval_exec_usage()
    test_template_injection()
    test_command_injection_concatenation()