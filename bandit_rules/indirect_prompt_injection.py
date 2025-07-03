import bandit
from bandit.core import test_properties as test
import re

@test.checks('Call')
@test.test_id('B911')
def external_data_processing(context):
    """
    Detect processing of external data sources for AI prompts
    """
    data_sources = [
        'open', 'read', 'requests.get', 'urllib.request.urlopen',
        'sqlite3.connect', 'pymysql.connect'
    ]
    
    if context.call_function_name_qual in data_sources:
        return bandit.Issue(
            severity=bandit.HIGH,
            confidence=bandit.MEDIUM,
            text=(
                "Processing of external data from a potentially untrusted source. "
                "When used in AI prompts, this can lead to prompt injection. "
                f"Source: {context.call_function_name_qual}"
            ),
            lineno=context.node.lineno,
        )

import ast  
  
@test.checks('BinOp')  
@test.test_id('B912')  
def prompt_concatenation(context):  
    """  
    Detect string concatenation with external data in prompts  
    """  
    # Note: This check is very basic and may have false positives.  
    # It crudely checks if a variable name involved in concatenation contains "prompt".  
    if isinstance(context.node.op, ast.Add) and \
       any('prompt' in str(child).lower() for child in [getattr(context.node.left, 'id', ''), getattr(context.node.right, 'id', '')]):  
        return bandit.Issue(  
            severity=bandit.HIGH,  
            confidence=bandit.LOW,  
            text=(  
                "String concatenation is used to construct a prompt, which can "  
                "lead to prompt injection if one of the operands is user-controlled."  
            ),  
            lineno=context.node.lineno,  
        )

@test.checks('Call')
@test.test_id('B913')
def template_injection(context):
    """
    Detect template-based prompt construction with external inputs
    """
    # Note: This check for 'str.format' is basic. F-string detection is more complex.
    if context.call_function_name_qual.endswith('.format'):
        return bandit.Issue(
            severity=bandit.MEDIUM,
            confidence=bandit.LOW,
            text=(
                "Template-based prompt construction detected using '.format()'. "
                "Ensure that user-provided input is sanitized to prevent prompt injection."
            ),
            lineno=context.node.lineno,
        )

@test.checks('Call')
@test.test_id('B914')
def document_processing(context):
    """
    Detect document processing for AI prompts without sanitization
    """
    doc_processors = [
        'pdfplumber.open', 'docx.Document', 'PyPDF2.PdfReader',
        'BeautifulSoup', 'lxml.etree.parse'
    ]
    
    if context.call_function_name_qual in doc_processors:
        return bandit.Issue(
            severity=bandit.HIGH,
            confidence=bandit.MEDIUM,
            text=(
                "Processing of documents (e.g., PDF, DOCX, XML, HTML) detected. "
                "Content from these documents, if used in AI prompts without sanitization, "
                "can lead to prompt injection."
            ),
            lineno=context.node.lineno,
        )


@test.checks('Call')
@test.test_id('B915')
def web_scraping_for_prompts(context):
    """
    Detect web scraping results fed directly to AI prompts
    """
    if context.call_function_name_qual in ['requests.get', 'selenium.webdriver.remote.webdriver.WebDriver.get']:
        return bandit.Issue(
            severity=bandit.HIGH,
            confidence=bandit.MEDIUM,
            text=(
                "Web scraping results may be used in AI prompts. Scraped content is "
                "untrusted and can be manipulated to perform prompt injection attacks."
            ),
            lineno=context.node.lineno,
        )