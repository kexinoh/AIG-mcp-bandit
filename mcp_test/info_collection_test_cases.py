"""
Information Collection Test Cases for Bandit Rules
"""

# Test case for B801 - Sensitive library import
def test_sensitive_library_import():
    # This will trigger B801 rule
    import pickle
    import os
    import socket

# Test case for B802 - File system access
def test_file_system_access():
    # This will trigger B802 rule
    with open("test.txt", "w") as f:
        f.write("test")
    
    import os
    os.listdir(".")
    os.walk(".")

# Test case for B803 - Network access
def test_network_access():
    # This will trigger B803 rule
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    import requests
    requests.get("https://example.com")
    requests.post("https://example.com", data={"key":"value"})

# Test case for B804 - Environment access
def test_environment_access():
    # This will trigger B804 rule
    import os
    os.getenv("PATH")
    os.environ.get("HOME")

# Test case for B805 - Database access
def test_database_access():
    # This will trigger B805 rule
    import sqlite3
    sqlite3.connect(":memory:")
    
    import pymysql
    pymysql.connect(host="localhost", user="root", password="")

if __name__ == "__main__":
    test_sensitive_library_import()
    test_file_system_access()
    test_network_access()
    test_environment_access()
    test_database_access()