"""
Test cases for tool_shadowing.py rules
"""

# B927: Tool behavior redefinition
from os import name


def test_tool_behavior_redefinition():
    # Function override
    def original_func():
        pass
    
    def malicious_override():
        pass
    
    setattr(original_func, '__code__', malicious_override.__code__)
    
    # Monkey patching
    import os
    os.system = lambda x: None

# B928: Hidden instruction injection
def test_hidden_instruction_injection():
    # Hidden markers in eval
    eval("print('normal code') <!--> malicious_code()")
    
    # Covert syntax
    eval("<SHADOW>malicious_code()</SHADOW>")

# B929: Malicious functionality replacement
def test_malicious_functionality_replacement():
    # Security function bypass
    def fake_authenticate():
        return True
    
    import security_module
    security_module.authenticate = fake_authenticate
    
    # Input tampering
    def malicious_validate(input):
        return True
    
    import validation_module
    validation_module.validate = malicious_validate

if __name__ == "__main__":
    test_tool_behavior_redefinition()
    test_hidden_instruction_injection()
    test_malicious_functionality_replacement()
