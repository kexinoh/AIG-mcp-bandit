import bandit
from bandit.core import test_properties as test

# MCP Command Injection Rules for Bandit

@test.checks('Call')
@test.test_id('C601')
def os_system_usage(context):
    """Detect usage of os.system()"""
    if context.call_function_name_qual == 'os.system':
        return bandit.Issue(
            severity=bandit.HIGH,
            confidence=bandit.HIGH,
            text="Using os.system() to execute system commands directly may lead to command injection.",
            lineno=context.node.lineno,
        )

@test.checks('Call')
@test.test_id('C602')
def subprocess_usage(context):
    """Detect usage of subprocess module with shell=True"""
    if context.call_function_name_qual in ('subprocess.Popen',
                                         'subprocess.call',
                                         'subprocess.run',
                                         'subprocess.check_output',
                                         'subprocess.check_call') and \
       context.check_call_arg_value('shell', 'True'):
        return bandit.Issue(
            severity=bandit.HIGH,
            confidence=bandit.HIGH,
            text="Using subprocess module with shell=True may lead to command injection.",
            lineno=context.get_lineno_for_call_arg('shell'),
        )

@test.checks('Call')
@test.test_id('C603')
def eval_exec_usage(context):
    """Detect usage of eval() or exec()"""
    if context.call_function_name in ('eval', 'exec'):
        return bandit.Issue(
            severity=bandit.HIGH,
            confidence=bandit.HIGH,
            text="Using eval() or exec() to execute dynamic code may lead to code injection.",
            lineno=context.node.lineno,
        )

@test.checks('Call')
@test.test_id('C604')
def template_injection(context):
    """Detect potential template injection"""
    if context.call_function_name_qual in ('flask.render_template_string',
                                         'jinja2.Template',
                                         'django.template.Template'):
        return bandit.Issue(
            severity=bandit.MEDIUM,
            confidence=bandit.MEDIUM,
            text="Using template strings may lead to server-side template injection.",
            lineno=context.node.lineno,
        )

import ast  
  
@test.checks('Call')  
@test.test_id('C605')  
def command_injection_concatenation(context):  
    """Detect command injection through string concatenation"""  
    if context.call_function_name_qual in ('os.system', 'subprocess.Popen') and \
       isinstance(context.node.args[0], ast.BinOp) and \
       isinstance(context.node.args[0].op, ast.Add):  
        return bandit.Issue(  
            severity=bandit.HIGH,  
            confidence=bandit.MEDIUM,  
            text="Command execution with string concatenation may lead to command injection.",  
            lineno=context.node.lineno,  
        )