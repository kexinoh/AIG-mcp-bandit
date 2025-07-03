import bandit
from bandit.core import test_properties as test

# B921: Malicious Service Termination
@test.checks('Call')
@test.test_id('B921')
def malicious_service_termination(context):
    """
    Detects calls to exit() without arguments, which could be a way to
    maliciously terminate a service without standard cleanup or error codes.
    """
    if (context.call_function_name_qual == 'builtins.exit' and
            not context.node.args and
            not context.node.keywords):
        return bandit.Issue(
            severity=bandit.HIGH,
            confidence=bandit.MEDIUM,
            text=f"Malicious service termination pattern detected: an empty call to '{context.call_function_name}'. "
                 "This can abruptly halt the application, bypassing normal shutdown procedures.",
            lineno=context.node.lineno,
        )

# B922: Resource Withdrawal
@test.checks('Call')
@test.test_id('B922')
def resource_withdrawal(context):
    """
    Detects function calls that can delete files or entire directory trees,
    representing a potential resource withdrawal attack.
    """
    dangerous_calls = ['os.remove', 'shutil.rmtree', 'os.unlink']
    if context.call_function_name_qual in dangerous_calls:
        return bandit.Issue(
            severity=bandit.HIGH,
            confidence=bandit.LOW,  # LOW confidence because these are common, legitimate functions.
            text=f"Potential resource withdrawal: the function '{context.call_function_name_qual}' is used to delete "
                 "files or directories. Ensure this is not exploitable.",
            lineno=context.node.lineno,
        )