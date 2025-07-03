import bandit
from bandit.core import test_properties as test

@test.checks('Call')
@test.test_id('B901')
def sensitive_credential_access(context):
    """
    Detect sensitive credential access patterns
    Severity: HIGH
    """
    patterns = [
        r'(\.env|config\.(ini|json|yml)|(secrets|credentials|password|token|\.bashrc|\.profile))',
        r'(\/etc\/passwd|\/etc\/shadow|\/etc\/httpd\/|\/etc\/.*\.conf(\&|\b)|\/usr\/local\/|\/var\/lib\/|~\.ssh)'
    ]
    
    for pattern in patterns:
        if context.call_function_name_qual in ['open', 'os.open'] and \
           context.check_call_arg_value('path', pattern):
            return bandit.Issue(
                severity=bandit.HIGH,
                confidence=bandit.MEDIUM,
                text="Potential sensitive credential access pattern detected",
                lineno=context.get_lineno_for_call_arg('path'),
            )
    
    return False

@test.checks('Call')
@test.test_id('B902')
def credential_keywords(context):
    """
    Detect credential related keywords
    Severity: MEDIUM
    """
    keywords = [
        r'\b(id_rsa|\.cursor\/mcp\.json|\.cursor\/|\bmcp\.json|api[ -_]?key|access[ -_]?key|auth[ -_]?token)\b'
    ]
    
    for keyword in keywords:
        if context.string_val and context.string_val.match(keyword):
            return bandit.Issue(
                severity=bandit.MEDIUM,
                confidence=bandit.MEDIUM,
                text="Potential credential keyword detected",
                lineno=context.node.lineno,
            )
    
    return False

@test.checks('Call')
@test.test_id('B903')
def credential_transmission(context):
    """
    Detect credential transmission patterns
    Severity: HIGH
    """
    if context.call_function_name_qual in ['requests.post', 'socket.send'] and \
       context.check_call_arg_value('data', r'(api[ -_]?key|access[ -_]?key|auth[ -_]?token)'):
        return bandit.Issue(
            severity=bandit.HIGH,
            confidence=bandit.HIGH,
            text="Potential credential transmission detected",
            lineno=context.get_lineno_for_call_arg('data'),
        )
    
    return False

@test.checks('Call')
@test.test_id('B904')
def environment_variable_access(context):
    """
    Detect sensitive environment variable access
    Severity: MEDIUM
    """
    if context.call_function_name_qual == 'os.environ.get' and \
       context.check_call_arg_value('key', r'(API[ -_]?KEY|ACCESS[ -_]?KEY|AUTH[ -_]?TOKEN)'):
        return bandit.Issue(
            severity=bandit.MEDIUM,
            confidence=bandit.MEDIUM,
            text="Potential sensitive environment variable access detected",
            lineno=context.get_lineno_for_call_arg('key'),
        )
    
    return False