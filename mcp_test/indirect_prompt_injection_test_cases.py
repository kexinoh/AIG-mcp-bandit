"""
Indirect Prompt Injection Test Cases for Bandit Rules
"""

# Test case for B911 - External data processing
def test_external_data_processing():
    # This will trigger B911 rule
    with open("user_data.txt", "r") as f:
        data = f.read()
    
    import requests
    response = requests.get("https://example.com/api/data")

# Test case for B912 - Prompt concatenation
def test_prompt_concatenation():
    # This will trigger B912 rule
    user_input = "malicious input"
    prompt = "Analyze this: " + user_input

# Test case for B913 - Template injection
def test_template_injection():
    # This will trigger B913 rule
    user_input = "malicious input"
    prompt = f"Analyze {user_input}"
    prompt2 = "Analyze {}".format(user_input)

# Test case for B914 - Document processing
def test_document_processing():
    # This will trigger B914 rule
    import PyPDF2
    pdf = PyPDF2.PdfReader("document.pdf")
    
    from docx import Document
    doc = Document("document.docx")

# Test case for B915 - Web scraping for prompts
def test_web_scraping_for_prompts():
    # This will trigger B915 rule
    import requests
    response = requests.get("https://example.com")
    prompt = "Analyze this webpage: " + response.text

if __name__ == "__main__":
    test_external_data_processing()
    test_prompt_concatenation()
    test_template_injection()
    test_document_processing()
    test_web_scraping_for_prompts()