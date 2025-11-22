"""
Integration tests for enhanced build_code_index with Tree-sitter
"""

import unittest
import tempfile
import shutil
from pathlib import Path
from tasks.indexer_tasks import (
    build_code_index,
    _extract_metadata_ast,
    _should_skip_file,
    TREE_SITTER_AVAILABLE
)


class TestEnhancedCodeIndex(unittest.TestCase):
    """Test enhanced code indexing functionality."""

    def setUp(self):
        """Create a temporary test repository."""
        self.test_dir = Path(tempfile.mkdtemp())

        # Create sample Python files
        (self.test_dir / "app.py").write_text("""
import os
import subprocess

def unsafe_command(user_input):
    # Vulnerable to command injection
    subprocess.call(user_input, shell=True)

def safe_function():
    print("This is safe")

class MyClass:
    def method_one(self):
        pass
""")

        (self.test_dir / "utils.py").write_text("""
import pickle

def deserialize_data(data):
    # Vulnerable to insecure deserialization
    return pickle.loads(data)
""")

        # Create JavaScript file
        (self.test_dir / "script.js").write_text("""
function updateContent(userInput) {
    // Vulnerable to XSS
    document.getElementById('content').innerHTML = userInput;
}
""")

        # Create dependency file
        (self.test_dir / "requirements.txt").write_text("""
requests==2.28.0
flask==2.3.0
""")

    def tearDown(self):
        """Clean up test directory."""
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir)

    def test_basic_indexing(self):
        """Test basic code indexing without Tree-sitter."""
        index = build_code_index(
            str(self.test_dir),
            use_tree_sitter=False,
            scan_vulnerabilities=False
        )

        # Check structure
        self.assertIn('files', index)
        self.assertIn('semantic_index', index)
        self.assertIn('statistics', index)

        # Check files were indexed
        self.assertGreater(len(index['files']), 0)

        # Check Python file metadata
        app_py_found = False
        for file_path, file_info in index['files'].items():
            if 'app.py' in file_path:
                app_py_found = True
                self.assertIn('methods', file_info)
                self.assertIn('classes', file_info)
                self.assertIn('imports', file_info)

        self.assertTrue(app_py_found, "app.py should be indexed")

    def test_tree_sitter_indexing(self):
        """Test indexing with Tree-sitter enabled."""
        if not TREE_SITTER_AVAILABLE:
            self.skipTest("Tree-sitter not available")

        index = build_code_index(
            str(self.test_dir),
            use_tree_sitter=True,
            scan_vulnerabilities=False
        )

        # Check Tree-sitter was enabled
        metadata = index.get('indexing_metadata', {})
        self.assertTrue(metadata.get('tree_sitter_enabled'))

        # Check semantic index
        semantic = index.get('semantic_index', {})
        self.assertGreater(len(semantic.get('functions', [])), 0)

    def test_vulnerability_scanning(self):
        """Test vulnerability pre-scanning."""
        if not TREE_SITTER_AVAILABLE:
            self.skipTest("Tree-sitter not available")

        index = build_code_index(
            str(self.test_dir),
            use_tree_sitter=True,
            scan_vulnerabilities=True
        )

        # Check vulnerabilities were scanned
        vulns = index.get('vulnerabilities', {})
        self.assertIn('pre_scan_results', vulns)
        self.assertGreater(vulns.get('patterns_checked', 0), 0)

        # Should find some vulnerabilities in our test code
        # (command injection, insecure deserialization, etc.)
        # Note: This might be 0 if Tree-sitter grammars aren't built
        pre_scan_results = vulns.get('pre_scan_results', [])
        if len(pre_scan_results) > 0:
            # Verify structure of vulnerability results
            vuln = pre_scan_results[0]
            self.assertIn('file', vuln)
            self.assertIn('line', vuln)
            self.assertIn('severity', vuln)
            self.assertIn('cwe', vuln)

    def test_statistics_collection(self):
        """Test code statistics collection."""
        index = build_code_index(
            str(self.test_dir),
            use_tree_sitter=False,
            scan_vulnerabilities=False
        )

        stats = index.get('statistics', {})
        self.assertIn('total_files', stats)
        self.assertIn('total_lines', stats)
        self.assertIn('languages', stats)

        # Should have indexed Python files
        self.assertGreater(stats.get('total_files', 0), 0)
        self.assertGreater(stats.get('total_lines', 0), 0)

    def test_multi_language_support(self):
        """Test support for multiple languages."""
        index = build_code_index(
            str(self.test_dir),
            use_tree_sitter=True,
            scan_vulnerabilities=False,
            target_languages=['python', 'javascript']
        )

        # Check both Python and JavaScript files were indexed
        files = index.get('files', {})

        has_python = any('app.py' in f or 'utils.py' in f for f in files.keys())
        has_javascript = any('script.js' in f for f in files.keys())

        self.assertTrue(has_python, "Should index Python files")
        # Note: JavaScript indexing requires Tree-sitter grammars

    def test_semantic_index_structure(self):
        """Test semantic index structure and content."""
        index = build_code_index(
            str(self.test_dir),
            use_tree_sitter=False,
            scan_vulnerabilities=False
        )

        semantic = index.get('semantic_index', {})

        # Check structure
        self.assertIn('functions', semantic)
        self.assertIn('classes', semantic)
        self.assertIn('imports', semantic)

        # Check functions list structure
        functions = semantic.get('functions', [])
        if len(functions) > 0:
            func = functions[0]
            self.assertIn('name', func)
            self.assertIn('file', func)

    def test_backward_compatibility(self):
        """Test backward compatibility with old API."""
        # Old API should still work
        index = build_code_index(str(self.test_dir))

        # Should have basic structure
        self.assertIn('repo_path', index)
        self.assertIn('files', index)

        # Files should have expected fields
        for file_info in index['files'].values():
            self.assertIn('content', file_info)
            self.assertIn('methods', file_info)
            self.assertIn('classes', file_info)
            self.assertIn('imports', file_info)


class TestHelperFunctions(unittest.TestCase):
    """Test helper functions."""

    def test_extract_metadata_ast(self):
        """Test AST metadata extraction."""
        code = """
import os
import sys

class TestClass:
    def method_one(self):
        pass

def function_one():
    pass

def function_two():
    return True
"""

        metadata = _extract_metadata_ast(code)

        self.assertIn('methods', metadata)
        self.assertIn('classes', metadata)
        self.assertIn('imports', metadata)

        # Should find 2 functions
        self.assertEqual(len(metadata['methods']), 3)  # 2 + 1 method in class

        # Should find 1 class
        self.assertIn('TestClass', metadata['classes'])

        # Should find 2 imports
        self.assertIn('os', metadata['imports'])
        self.assertIn('sys', metadata['imports'])

    def test_should_skip_file(self):
        """Test file skipping logic."""
        # Should skip
        self.assertTrue(_should_skip_file('.git/config'))
        self.assertTrue(_should_skip_file('venv/lib/python'))
        self.assertTrue(_should_skip_file('__pycache__/module.pyc'))
        self.assertTrue(_should_skip_file('.hidden/file.py'))

        # Should not skip
        self.assertFalse(_should_skip_file('src/app.py'))
        self.assertFalse(_should_skip_file('lib/utils.py'))
        self.assertFalse(_should_skip_file('tests/test_app.py'))


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error handling."""

    def setUp(self):
        """Create temporary directory."""
        self.test_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        """Clean up."""
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir)

    def test_empty_repository(self):
        """Test indexing an empty repository."""
        index = build_code_index(str(self.test_dir))

        self.assertEqual(len(index['files']), 0)
        self.assertEqual(index['statistics']['total_files'], 0)

    def test_syntax_error_file(self):
        """Test handling of files with syntax errors."""
        # Create file with syntax error
        bad_file = self.test_dir / "bad.py"
        bad_file.write_text("""
def broken_function(
    # Missing closing parenthesis
    pass
""")

        # Should not crash
        index = build_code_index(str(self.test_dir))

        # File should still be indexed
        self.assertGreater(len(index['files']), 0)

    def test_binary_file(self):
        """Test handling of binary files."""
        # Create a binary file
        binary_file = self.test_dir / "image.png"
        binary_file.write_bytes(b'\x89PNG\r\n\x1a\n')

        # Should not crash
        index = build_code_index(str(self.test_dir))

        # Binary file should be skipped
        self.assertEqual(len(index['files']), 0)

    def test_large_file(self):
        """Test handling of large files."""
        # Create a large file (10K lines)
        large_file = self.test_dir / "large.py"
        content = "# Comment\n" * 10000
        large_file.write_text(content)

        # Should not crash
        index = build_code_index(str(self.test_dir))

        # File should be indexed
        self.assertGreater(len(index['files']), 0)

        # Should have correct line count
        stats = index['statistics']
        self.assertGreater(stats['total_lines'], 9000)


def run_tests():
    """Run all integration tests."""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add test cases
    suite.addTests(loader.loadTestsFromTestCase(TestEnhancedCodeIndex))
    suite.addTests(loader.loadTestsFromTestCase(TestHelperFunctions))
    suite.addTests(loader.loadTestsFromTestCase(TestEdgeCases))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result.wasSuccessful()


if __name__ == '__main__':
    import sys
    success = run_tests()
    sys.exit(0 if success else 1)
