import bandit
from bandit.core import test_properties as test
import re

@test.checks('Str')
@test.test_id('B906')
def aws_key_detection(context):
    """
    Detect AWS access keys
    Severity: HIGH
    """
    aws_pattern = r'(AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[0-9A-Z]{16}'
    if re.match(aws_pattern, context.string_val):
        return bandit.Issue(
            severity=bandit.HIGH,
            confidence=bandit.HIGH,
            text="Potential AWS access key detected",
            lineno=context.node.lineno,
        )
    return False

@test.checks('Str')
@test.test_id('B907')
def github_token_detection(context):
    """
    Detect GitHub personal access tokens
    Severity: HIGH
    """
    github_pattern = r'(ghp|gho|ghu|ghs)_[a-zA-Z0-9]{36}'
    if re.match(github_pattern, context.string_val):
        return bandit.Issue(
            severity=bandit.HIGH,
            confidence=bandit.HIGH,
            text="Potential GitHub token detected",
            lineno=context.node.lineno,
        )
    return False

@test.checks('Str')
@test.test_id('B908')
def openai_key_detection(context):
    """
    Detect OpenAI API keys
    Severity: HIGH
    """
    openai_pattern = r'sk-(proj|ant-api|ant)-[a-zA-Z0-9]{48}'
    if re.match(openai_pattern, context.string_val):
        return bandit.Issue(
            severity=bandit.HIGH,
            confidence=bandit.HIGH,
            text="Potential OpenAI API key detected",
            lineno=context.node.lineno,
        )
    return False

@test.checks('Assign')  
@test.test_id('B909')  
def sensitive_variable_assignment(context):  
    """  
    Detect sensitive variable assignments  
    Severity: MEDIUM  
    """  
    sensitive_names = [  
        'api_key', 'secret_key', 'access_key',  
        'auth_token', 'password', 'credentials'  
    ]  
      
    # Check if this is a simple assignment with a single target  
    if len(context.node.targets) == 1:  
        target = context.node.targets[0]  
        # Check if target is a simple name (variable) and has string value  
        if (hasattr(target, 'id') and   
            target.id in sensitive_names and  
            hasattr(context.node.value, 's') and  
            len(context.node.value.s) > 10):  
            return bandit.Issue(  
                severity=bandit.MEDIUM,  
                confidence=bandit.MEDIUM,  
                text="Potential sensitive variable assignment detected",  
                lineno=context.node.lineno,  
            )  
    return None

@test.checks('Call')
@test.test_id('B910')
def auth_header_detection(context):
    """
    Detect hardcoded auth headers
    Severity: HIGH
    """
    if context.call_function_name_qual == 'requests.get' and \
       context.check_call_arg_value('headers', r'Bearer [a-zA-Z0-9]{20,}'):
        return bandit.Issue(
            severity=bandit.HIGH,
            confidence=bandit.HIGH,
            text="Potential hardcoded auth header detected",
            lineno=context.get_lineno_for_call_arg('headers'),
        )
    return False