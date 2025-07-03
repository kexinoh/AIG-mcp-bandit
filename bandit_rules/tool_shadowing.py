import bandit
from bandit.core import test_properties as test
import ast

@test.checks('Call')
@test.test_id('B927')
def tool_behavior_redefinition(context):
    """
    Detect tool behavior redefinition (B927)
    - Function override/overwrite
    - Dynamic proxy/interception
    """
    suspicious_keywords = ['override', 'monkey_patch', 'redefine']
    if (context.call_function_name in ['setattr', '__setattr__'] or
        any(kw in context.string_val for kw in suspicious_keywords if context.string_val)):
        return bandit.Issue(
            severity=bandit.HIGH,
            confidence=bandit.MEDIUM,
            text=f"Detected potential tool behavior redefinition: {context.call_function_name}",
            lineno=context.node.lineno
        )

@test.checks('Call')
@test.test_id('B928')
def hidden_instruction_injection(context):
    """
    Detect hidden instruction injection (B928)
    - Special markers/covert syntax
    - Malicious cross-tool communication
    """
    if (context.call_function_name == 'eval' and
        any('<!-->' in arg.value.s or '<SHADOW>' in arg.value.s
            for arg in context.node.args
            if hasattr(arg, 'value') and hasattr(arg.value, 's'))):
        return bandit.Issue(
            severity=bandit.MEDIUM,
            confidence=bandit.LOW,
            text=f"Detected potential hidden instruction injection: {context.call_function_name}",
            lineno=context.node.lineno
        )

@test.checks('Call')
@test.test_id('B929')
def malicious_functionality_replacement(context):
    """
    Detect malicious functionality replacement (B929)
    - Security function bypass
    - Input/output tampering
    """
    security_functions = ['authenticate', 'validate', 'verify']
    if (context.call_function_name in security_functions and
        context.call_function_name_qual != context.call_function_name):
        return bandit.Issue(
            severity=bandit.HIGH,
            confidence=bandit.HIGH,
            text=f"Detected potential malicious functionality replacement: {context.call_function_name}",
            lineno=context.node.lineno
        )