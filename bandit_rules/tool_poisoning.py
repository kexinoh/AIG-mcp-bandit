import bandit
from bandit.core import test_properties as test

@test.checks('Call')
@test.test_id('B924')
def tool_function_manipulation(context):
    """
    Detect tool functionality manipulation (B924)
    - Modification of legitimate tool behavior
    - Injection of malicious code
    """
    suspicious_patterns = ['eval', 'exec', 'os.system', 'subprocess.Popen']
    if context.call_function_name_qual in suspicious_patterns:
        return bandit.Issue(
            severity=bandit.HIGH,
            confidence=bandit.MEDIUM,
            text=f"Detected potential tool manipulation: {context.call_function_name_qual}",
            lineno=context.node.lineno
        )

@test.checks('Call')
@test.test_id('B925')
def covert_malicious_behavior(context):
    """
    Detect covert malicious behavior (B925)
    - Conditional execution based on triggers
    - Data exfiltration disguised as normal ops
    """
    if (context.call_function_name == 'requests.get' and 
        any(arg.value.s.lower().startswith('http') 
            for arg in context.node.args 
            if hasattr(arg, 'value') and hasattr(arg.value, 's'))):
        return bandit.Issue(
            severity=bandit.MEDIUM,
            confidence=bandit.LOW,
            text=f"Detected potential covert behavior: {context.call_function_name}",
            lineno=context.node.lineno
        )

@test.checks('Call')
@test.test_id('B926')
def stealth_mechanisms(context):
    """
    Detect stealth mechanisms (B926)
    - Obfuscated code
    - Environmental checks to hide behavior
    """
    if (context.call_function_name == 'getattr' and 
        len(context.node.args) > 1 and 
        hasattr(context.node.args[1], 'value') and 
        isinstance(context.node.args[1].value, str) and 
        context.node.args[1].value in ['system', 'exec', 'eval']):
        return bandit.Issue(
            severity=bandit.LOW,
            confidence=bandit.MEDIUM,
            text=f"Detected potential stealth mechanism: {context.call_function_name}",
            lineno=context.node.lineno
        )