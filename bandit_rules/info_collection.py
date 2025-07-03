import bandit
from bandit.core import test_properties as test

# MCP Information Collection Rules for Bandit

@test.checks('Import')  
@test.test_id('B801')  
def sensitive_library_import(context):  
    """Detect import of sensitive libraries"""  
    sensitive_libs = ['pickle', 'marshal', 'subprocess', 'os', 'sys', 'socket']  
    for lib in sensitive_libs:  
        if context.is_module_being_imported(lib):  
            return bandit.Issue(  
                severity=bandit.MEDIUM,  
                confidence=bandit.HIGH,  
                text=f"Import of sensitive library {lib} detected",  
                lineno=context.node.lineno,  
            )
@test.checks('Call')
@test.test_id('B802')
def file_system_access(context):
    """Detect file system access operations"""
    fs_operations = ['open', 'os.open', 'os.listdir', 'os.walk', 'os.remove']
    if context.call_function_name_qual in fs_operations:
        return bandit.Issue(
            severity=bandit.MEDIUM,
            confidence=bandit.MEDIUM,
            text=f"File system operation {context.call_function_name_qual} detected",
            lineno=context.get_lineno_for_call_arg('path'),
        )

@test.checks('Call')
@test.test_id('B803')
def network_access(context):
    """Detect network access operations"""
    network_operations = ['socket.socket', 'requests.get', 'requests.post', 
                         'urllib.request.urlopen']
    if context.call_function_name_qual in network_operations:
        return bandit.Issue(
            severity=bandit.MEDIUM,
            confidence=bandit.MEDIUM,
            text=f"Network operation {context.call_function_name_qual} detected",
            lineno=context.get_lineno_for_call_arg('url'),
        )

@test.checks('Call')
@test.test_id('B804')
def environment_access(context):
    """Detect environment variable access"""
    if context.call_function_name_qual in ('os.getenv', 'os.environ.get'):
        return bandit.Issue(
            severity=bandit.LOW,
            confidence=bandit.MEDIUM,
            text="Environment variable access detected",
            lineno=context.get_lineno_for_call_arg('key'),
        )

@test.checks('Call')
@test.test_id('B805')
def database_access(context):
    """Detect database access operations"""
    db_operations = ['sqlite3.connect', 'psycopg2.connect', 'pymysql.connect']
    if context.call_function_name_qual in db_operations:
        return bandit.Issue(
            severity=bandit.HIGH,
            confidence=bandit.MEDIUM,
            text=f"Database operation {context.call_function_name_qual} detected",
            lineno=context.get_lineno_for_call_arg('database'),
        )

# Additional rules can be added here following the same pattern
# Each rule should have a unique test_id (B8xx series for info collection rules)
# and appropriate severity/confidence levels