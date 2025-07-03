#
# A test plugin for bandit to find common authentication bypass issues.
#

import bandit
from bandit.core import test_properties as test

@test.checks('Str')  
@test.test_id('C701')  
def hardcoded_credentials(context):  
    """Detect hardcoded credentials"""  
    if context.string_val.lower() in ('password', 'secret', 'token', 'api_key'):  
        return bandit.Issue(  
            severity=bandit.HIGH,  
            confidence=bandit.MEDIUM,  
            text="Potential hardcoded credential found: " + context.string_val,  
            lineno=context.node.lineno,  
        )

        
@test.checks('Call')  
@test.test_id('C702')  
def jwt_insecure_usage(context):  
    """Detect insecure JWT usage"""  
    if context.call_function_name_qual == 'jwt.decode':  
        if context.check_call_arg_value('verify', 'False'):  
            return bandit.Issue(  
                severity=bandit.HIGH,  
                confidence=bandit.HIGH,  
                text="Insecure JWT usage with verify=False",  
                lineno=context.get_lineno_for_call_arg('verify'),  
            )

@test.checks('Call')
@test.test_id('C703')
def session_authentication_bypass(context):
    """Detect session authentication bypass"""
    # 你的 B703 实现
    # 你的原始实现可能不够精确，可以改进为检查赋值操作
    # 这里暂时保留你的逻辑
    if context.call_function_name == 'session' and 'authenticated' in context.call_args_string and 'True' in context.call_args_string:
         return bandit.Issue(
            severity=bandit.MEDIUM,
            confidence=bandit.MEDIUM,
            text="Potential session authentication bypass",
            lineno=context.get_lineno_for_metric(),
         )

@test.checks('FunctionDef')
@test.test_id('C704')
def missing_authentication_decorator(context):
    """Detect missing authentication decorators"""
    if context.node.name.startswith('admin_'):
        # 简单实现，只检查是否存在名为 'login_required' 的装饰器
        found_decorator = False
        for decorator in context.node.decorator_list:
            # 这是一个简化的检查，可能需要根据实际代码进行调整
            if hasattr(decorator, 'id') and decorator.id == 'login_required':
                found_decorator = True
                break
        
        if not found_decorator:
            return bandit.Issue(
                severity=bandit.MEDIUM,
                confidence=bandit.LOW,
                text="Potential missing authentication decorator on admin function",
                lineno=context.node.lineno,
            )

