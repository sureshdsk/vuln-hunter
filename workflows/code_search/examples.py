"""Example usage of the Tree-sitter code search module."""

from pathlib import Path
from .parser import CodeParser
from .searcher import CodeSearcher
from .query_builder import QueryBuilder
from .patterns import VulnerabilityPatterns


def example_basic_parsing():
    """Example: Basic code parsing."""
    print("=== Example 1: Basic Code Parsing ===\n")

    parser = CodeParser()

    # Parse a Python file
    code = b"""
def calculate_sum(a, b):
    return a + b

class Calculator:
    def multiply(self, x, y):
        return x * y
"""

    root_node = parser.parse_code(code, 'python')
    if root_node:
        print(f"Parsed tree type: {root_node.type}")
        print(f"Number of children: {len(root_node.children)}")

        # Traverse and print all nodes
        def print_node(node, depth):
            indent = "  " * depth
            text = parser.get_node_text(node, code).replace('\n', '\\n')[:50]
            print(f"{indent}{node.type}: {text}")

        parser.traverse_tree(root_node, print_node)


def example_find_functions():
    """Example: Find all function definitions."""
    print("\n=== Example 2: Find Function Definitions ===\n")

    # Create a test file
    test_code = Path("test_sample.py")
    test_code.write_text("""
def hello_world():
    print("Hello, World!")

def add_numbers(x, y):
    return x + y

class MyClass:
    def method_one(self):
        pass

    def method_two(self, arg):
        return arg * 2
""")

    searcher = CodeSearcher()
    results = searcher.find_function_definitions(test_code)

    print(f"Found {len(results)} functions:")
    for result in results:
        print(f"  - {result.text} at line {result.line_number}")

    # Cleanup
    test_code.unlink()


def example_find_imports():
    """Example: Find import statements."""
    print("\n=== Example 3: Find Import Statements ===\n")

    test_code = Path("test_imports.py")
    test_code.write_text("""
import os
import sys
from pathlib import Path
from typing import List, Dict
""")

    searcher = CodeSearcher()
    results = searcher.find_imports(test_code)

    print(f"Found {len(results)} import statements:")
    for result in results:
        print(f"  - {result.text.strip()} at line {result.line_number}")

    test_code.unlink()


def example_custom_query():
    """Example: Using custom Tree-sitter queries."""
    print("\n=== Example 4: Custom Tree-sitter Query ===\n")

    test_code = Path("test_query.py")
    test_code.write_text("""
def test_login():
    assert True

def test_user_creation():
    user = create_user()
    assert user is not None

def helper_function():
    pass
""")

    # Find all functions that start with 'test_'
    searcher = CodeSearcher()

    # Using query builder
    query = QueryBuilder.function_with_name("test_login", "python")
    print(f"Query pattern:\n{query}\n")

    # Or use a custom pattern to find all test functions
    pattern = """
    (function_definition
      name: (identifier) @func_name)
    (#match? @func_name "^test_")
    """

    results = searcher.search_pattern(pattern, test_code, "python")

    print(f"Found {len(results)} test functions:")
    for result in results:
        print(f"  - {result.text} at line {result.line_number}")

    test_code.unlink()


def example_vulnerability_detection():
    """Example: Detect potential vulnerabilities."""
    print("\n=== Example 5: Vulnerability Detection ===\n")

    test_code = Path("test_vuln.py")
    test_code.write_text("""
import subprocess
import pickle
import hashlib

def unsafe_command(user_input):
    # Vulnerable to command injection
    subprocess.call(user_input, shell=True)

def unsafe_deserialization(data):
    # Vulnerable to insecure deserialization
    return pickle.loads(data)

def weak_crypto(password):
    # Using weak hashing algorithm
    return hashlib.md5(password.encode()).hexdigest()

API_KEY = "hardcoded-secret-key-12345"
""")

    searcher = CodeSearcher()

    # Get all vulnerability patterns for Python
    all_patterns = VulnerabilityPatterns.get_patterns_for_language("python")

    print(f"Scanning with {len(all_patterns)} vulnerability patterns...\n")

    vulnerabilities_found = []

    for pattern in all_patterns:
        try:
            results = searcher.search_pattern(pattern.query, test_code, "python")
            if results:
                for result in results:
                    vulnerabilities_found.append({
                        'pattern': pattern.name,
                        'severity': pattern.severity,
                        'cwe': pattern.cwe,
                        'line': result.line_number,
                        'code': result.text[:80]
                    })
        except Exception as e:
            # Some patterns might not match the syntax tree
            pass

    if vulnerabilities_found:
        print(f"Found {len(vulnerabilities_found)} potential vulnerabilities:")
        for vuln in vulnerabilities_found:
            print(f"\n  [{vuln['severity'].upper()}] {vuln['pattern']}")
            print(f"  CWE: {vuln['cwe']}")
            print(f"  Line: {vuln['line']}")
            print(f"  Code: {vuln['code']}")
    else:
        print("No vulnerabilities detected.")

    test_code.unlink()


def example_directory_search():
    """Example: Search across multiple files in a directory."""
    print("\n=== Example 6: Directory-wide Search ===\n")

    # Create a test directory structure
    test_dir = Path("test_project")
    test_dir.mkdir(exist_ok=True)

    (test_dir / "app.py").write_text("""
def main():
    print("Main application")

def process_data(data):
    return data.upper()
""")

    (test_dir / "utils.py").write_text("""
def helper_one():
    pass

def helper_two():
    pass
""")

    # Search for all function definitions in the directory
    searcher = CodeSearcher()
    pattern = "(function_definition name: (identifier) @func_name)"

    results = searcher.search_directory(
        pattern=pattern,
        directory=test_dir,
        file_extensions=['.py']
    )

    print(f"Found {len(results)} functions across all files:")
    for result in results:
        print(f"  - {result.text} in {result.file_path.name} at line {result.line_number}")

    # Cleanup
    import shutil
    shutil.rmtree(test_dir)


def example_function_calls():
    """Example: Find specific function calls."""
    print("\n=== Example 7: Find Function Calls ===\n")

    test_code = Path("test_calls.py")
    test_code.write_text("""
import os

def main():
    print("Starting")
    result = os.system("ls -la")
    print("Done")
    print(result)
""")

    searcher = CodeSearcher()

    # Find all calls to 'print'
    results = searcher.find_function_calls(test_code, function_name="print")

    print(f"Found {len(results)} calls to 'print':")
    for result in results:
        print(f"  - {result.text} at line {result.line_number}")

    test_code.unlink()


def run_all_examples():
    """Run all examples."""
    examples = [
        example_basic_parsing,
        example_find_functions,
        example_find_imports,
        example_custom_query,
        example_vulnerability_detection,
        example_directory_search,
        example_function_calls,
    ]

    for example in examples:
        try:
            example()
        except Exception as e:
            print(f"\nError in {example.__name__}: {e}")

    print("\n" + "="*50)
    print("All examples completed!")


if __name__ == "__main__":
    run_all_examples()
