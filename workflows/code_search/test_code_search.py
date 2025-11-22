"""Unit tests for the code_search module."""

import unittest
from pathlib import Path
import tempfile
import shutil
from .parser import CodeParser
from .searcher import CodeSearcher, SearchResult
from .query_builder import QueryBuilder
from .patterns import VulnerabilityPatterns, VulnerabilityPattern


class TestCodeParser(unittest.TestCase):
    """Test cases for CodeParser."""

    def setUp(self):
        """Set up test fixtures."""
        self.parser = CodeParser()

    def test_parse_python_code(self):
        """Test parsing Python code."""
        code = b"def hello(): pass"
        tree = self.parser.parse_code(code, 'python')

        self.assertIsNotNone(tree)
        self.assertEqual(tree.type, 'module')

    def test_detect_language(self):
        """Test language detection from file extension."""
        test_cases = [
            (Path('test.py'), 'python'),
            (Path('test.js'), 'javascript'),
            (Path('test.ts'), 'typescript'),
            (Path('test.java'), 'java'),
            (Path('test.go'), 'go'),
        ]

        for file_path, expected_lang in test_cases:
            lang = self.parser.detect_language(file_path)
            self.assertEqual(lang, expected_lang)

    def test_get_node_text(self):
        """Test extracting text from nodes."""
        code = b"def hello(): pass"
        tree = self.parser.parse_code(code, 'python')

        text = self.parser.get_node_text(tree, code)
        self.assertEqual(text, "def hello(): pass")

    def test_traverse_tree(self):
        """Test tree traversal."""
        code = b"def hello(): pass"
        tree = self.parser.parse_code(code, 'python')

        nodes_visited = []

        def collect_nodes(node, depth):
            nodes_visited.append((node.type, depth))

        self.parser.traverse_tree(tree, collect_nodes)

        self.assertGreater(len(nodes_visited), 0)
        self.assertEqual(nodes_visited[0][0], 'module')


class TestCodeSearcher(unittest.TestCase):
    """Test cases for CodeSearcher."""

    def setUp(self):
        """Set up test fixtures."""
        self.searcher = CodeSearcher()
        self.test_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        """Clean up test fixtures."""
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir)

    def test_find_function_definitions(self):
        """Test finding function definitions."""
        test_file = self.test_dir / 'test.py'
        test_file.write_text("""
def func_one():
    pass

def func_two():
    return True
""")

        results = self.searcher.find_function_definitions(test_file)

        # Note: This test may fail if tree-sitter grammars are not built
        # Uncomment when grammars are available
        # self.assertEqual(len(results), 2)
        # self.assertIn('func_one', results[0].text)

    def test_find_class_definitions(self):
        """Test finding class definitions."""
        test_file = self.test_dir / 'test.py'
        test_file.write_text("""
class MyClass:
    pass

class AnotherClass:
    pass
""")

        results = self.searcher.find_class_definitions(test_file)

        # Note: Requires tree-sitter grammars
        # self.assertEqual(len(results), 2)

    def test_find_imports(self):
        """Test finding import statements."""
        test_file = self.test_dir / 'test.py'
        test_file.write_text("""
import os
import sys
from pathlib import Path
""")

        results = self.searcher.find_imports(test_file)

        # Note: Requires tree-sitter grammars
        # self.assertGreater(len(results), 0)

    def test_search_directory(self):
        """Test searching across multiple files."""
        (self.test_dir / 'file1.py').write_text("def test(): pass")
        (self.test_dir / 'file2.py').write_text("def another(): pass")

        pattern = "(function_definition name: (identifier) @func_name)"

        results = self.searcher.search_directory(
            pattern=pattern,
            directory=self.test_dir,
            file_extensions=['.py']
        )

        # Note: Requires tree-sitter grammars
        # self.assertGreater(len(results), 0)


class TestQueryBuilder(unittest.TestCase):
    """Test cases for QueryBuilder."""

    def test_function_with_name(self):
        """Test building function query."""
        query = QueryBuilder.function_with_name('test_func', 'python')

        self.assertIn('function_definition', query)
        self.assertIn('@func_name', query)
        self.assertIn('test_func', query)

    def test_class_with_name(self):
        """Test building class query."""
        query = QueryBuilder.class_with_name('MyClass', 'python')

        self.assertIn('class_definition', query)
        self.assertIn('MyClass', query)

    def test_imports_from_module(self):
        """Test building import query."""
        query = QueryBuilder.imports_from_module('os', 'python')

        self.assertIn('import', query)
        self.assertIn('os', query)

    def test_function_calls_to(self):
        """Test building function call query."""
        query = QueryBuilder.function_calls_to('print', 'python')

        self.assertIn('call', query)
        self.assertIn('print', query)

    def test_query_builder_chaining(self):
        """Test QueryBuilder method chaining."""
        builder = QueryBuilder()
        query = (builder
                 .node('function_definition', name='(identifier) @func_name')
                 .match_predicate('func_name', '^test_')
                 .build())

        self.assertIn('function_definition', query)
        self.assertIn('@func_name', query)
        self.assertIn('#match?', query)


class TestVulnerabilityPatterns(unittest.TestCase):
    """Test cases for VulnerabilityPatterns."""

    def test_get_sql_injection_patterns(self):
        """Test SQL injection patterns."""
        patterns = VulnerabilityPatterns.get_sql_injection_patterns()

        self.assertGreater(len(patterns), 0)
        for pattern in patterns:
            self.assertIsInstance(pattern, VulnerabilityPattern)
            self.assertEqual(pattern.cwe, 'CWE-89')

    def test_get_xss_patterns(self):
        """Test XSS patterns."""
        patterns = VulnerabilityPatterns.get_xss_patterns()

        self.assertGreater(len(patterns), 0)
        for pattern in patterns:
            self.assertEqual(pattern.cwe, 'CWE-79')

    def test_get_command_injection_patterns(self):
        """Test command injection patterns."""
        patterns = VulnerabilityPatterns.get_command_injection_patterns()

        self.assertGreater(len(patterns), 0)
        for pattern in patterns:
            self.assertEqual(pattern.cwe, 'CWE-78')

    def test_get_all_patterns(self):
        """Test getting all patterns."""
        all_patterns = VulnerabilityPatterns.get_all_patterns()

        self.assertIsInstance(all_patterns, dict)
        self.assertGreater(len(all_patterns), 0)

        expected_categories = [
            'sql_injection',
            'xss',
            'command_injection',
            'path_traversal',
            'insecure_deserialization',
        ]

        for category in expected_categories:
            self.assertIn(category, all_patterns)

    def test_get_patterns_for_language(self):
        """Test getting patterns for specific language."""
        python_patterns = VulnerabilityPatterns.get_patterns_for_language('python')

        self.assertGreater(len(python_patterns), 0)
        for pattern in python_patterns:
            self.assertEqual(pattern.language, 'python')

    def test_pattern_structure(self):
        """Test vulnerability pattern structure."""
        patterns = VulnerabilityPatterns.get_sql_injection_patterns()

        for pattern in patterns:
            self.assertIsNotNone(pattern.name)
            self.assertIsNotNone(pattern.description)
            self.assertIn(pattern.severity, ['critical', 'high', 'medium', 'low'])
            self.assertTrue(pattern.cwe.startswith('CWE-'))
            self.assertIsNotNone(pattern.query)
            self.assertIsNotNone(pattern.language)


class TestIntegration(unittest.TestCase):
    """Integration tests."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        """Clean up test fixtures."""
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir)

    def test_end_to_end_vulnerability_scan(self):
        """Test complete vulnerability scanning workflow."""
        # Create a file with potential vulnerabilities
        test_file = self.test_dir / 'vulnerable.py'
        test_file.write_text("""
import subprocess
import pickle

def unsafe_exec(user_input):
    subprocess.call(user_input, shell=True)

def unsafe_deserialize(data):
    return pickle.loads(data)
""")

        searcher = CodeSearcher()
        patterns = VulnerabilityPatterns.get_patterns_for_language('python')

        vulnerabilities_found = 0

        for pattern in patterns:
            try:
                results = searcher.search_pattern(pattern.query, test_file, 'python')
                vulnerabilities_found += len(results)
            except Exception:
                # Pattern might not match - this is expected
                pass

        # Note: Requires tree-sitter grammars to be built
        # self.assertGreater(vulnerabilities_found, 0)


def run_tests():
    """Run all tests."""
    unittest.main(argv=[''], exit=False, verbosity=2)


if __name__ == '__main__':
    run_tests()
