"""Code searcher using Tree-sitter queries."""

from pathlib import Path
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass
import tree_sitter
from tree_sitter import Node, Query

from .parser import CodeParser


@dataclass
class SearchResult:
    """Represents a search result."""

    file_path: Path
    line_number: int
    column: int
    node_type: str
    text: str
    context: Dict[str, Any]
    captures: Dict[str, Node]


class CodeSearcher:
    """Semantic code search using Tree-sitter queries."""

    def __init__(self, parser: Optional[CodeParser] = None):
        """
        Initialize the code searcher.

        Args:
            parser: CodeParser instance. If None, creates a new one.
        """
        self.parser = parser or CodeParser()

    def search_pattern(
        self,
        pattern: str,
        file_path: Path,
        language: Optional[str] = None
    ) -> List[SearchResult]:
        """
        Search for a specific pattern in a file using Tree-sitter query.

        Args:
            pattern: Tree-sitter query pattern (S-expression)
            file_path: Path to the file to search
            language: Programming language. Auto-detected if None.

        Returns:
            List of search results

        Example:
            pattern = "(function_definition name: (identifier) @func_name)"
        """
        if not file_path.exists():
            return []

        # Detect language if not provided
        if language is None:
            language = self.parser.detect_language(file_path)
            if not language:
                return []

        # Parse the file
        root_node = self.parser.parse_file(file_path)
        if not root_node:
            return []

        # Read source code
        with open(file_path, 'rb') as f:
            source_code = f.read()

        # Create and execute query
        try:
            lang = self.parser.languages[language]
            query = lang.query(pattern)
            captures = query.captures(root_node)

            results = []
            for node, capture_name in captures:
                text = self.parser.get_node_text(node, source_code)
                result = SearchResult(
                    file_path=file_path,
                    line_number=node.start_point[0] + 1,
                    column=node.start_point[1],
                    node_type=node.type,
                    text=text,
                    context={},
                    captures={capture_name: node}
                )
                results.append(result)

            return results

        except Exception as e:
            print(f"Error executing query on {file_path}: {e}")
            return []

    def search_directory(
        self,
        pattern: str,
        directory: Path,
        file_extensions: Optional[List[str]] = None,
        exclude_patterns: Optional[List[str]] = None
    ) -> List[SearchResult]:
        """
        Search for a pattern across multiple files in a directory.

        Args:
            pattern: Tree-sitter query pattern
            directory: Root directory to search
            file_extensions: List of file extensions to include (e.g., ['.py', '.js'])
            exclude_patterns: List of glob patterns to exclude (e.g., ['**/test_*'])

        Returns:
            List of search results from all matching files
        """
        results = []
        exclude_patterns = exclude_patterns or []

        for file_path in directory.rglob('*'):
            # Skip directories
            if not file_path.is_file():
                continue

            # Check file extension filter
            if file_extensions and file_path.suffix not in file_extensions:
                continue

            # Check exclude patterns
            if any(file_path.match(pattern) for pattern in exclude_patterns):
                continue

            # Detect language
            language = self.parser.detect_language(file_path)
            if not language:
                continue

            # Search in file
            file_results = self.search_pattern(pattern, file_path, language)
            results.extend(file_results)

        return results

    def find_function_definitions(self, file_path: Path) -> List[SearchResult]:
        """
        Find all function definitions in a file.

        Args:
            file_path: Path to the file

        Returns:
            List of function definitions found
        """
        language = self.parser.detect_language(file_path)
        if not language:
            return []

        # Language-specific patterns for function definitions
        patterns = {
            'python': '(function_definition name: (identifier) @func_name)',
            'javascript': '(function_declaration name: (identifier) @func_name)',
            'typescript': '(function_declaration name: (identifier) @func_name)',
            'java': '(method_declaration name: (identifier) @func_name)',
            'c': '(function_definition declarator: (function_declarator declarator: (identifier) @func_name))',
            'cpp': '(function_definition declarator: (function_declarator declarator: (identifier) @func_name))',
            'go': '(function_declaration name: (identifier) @func_name)',
            'rust': '(function_item name: (identifier) @func_name)',
        }

        pattern = patterns.get(language)
        if not pattern:
            return []

        return self.search_pattern(pattern, file_path, language)

    def find_class_definitions(self, file_path: Path) -> List[SearchResult]:
        """
        Find all class definitions in a file.

        Args:
            file_path: Path to the file

        Returns:
            List of class definitions found
        """
        language = self.parser.detect_language(file_path)
        if not language:
            return []

        # Language-specific patterns for class definitions
        patterns = {
            'python': '(class_definition name: (identifier) @class_name)',
            'javascript': '(class_declaration name: (identifier) @class_name)',
            'typescript': '(class_declaration name: (type_identifier) @class_name)',
            'java': '(class_declaration name: (identifier) @class_name)',
            'cpp': '(class_specifier name: (type_identifier) @class_name)',
            'go': '(type_declaration (type_spec name: (type_identifier) @class_name))',
            'rust': '(struct_item name: (type_identifier) @class_name)',
        }

        pattern = patterns.get(language)
        if not pattern:
            return []

        return self.search_pattern(pattern, file_path, language)

    def find_imports(self, file_path: Path) -> List[SearchResult]:
        """
        Find all import statements in a file.

        Args:
            file_path: Path to the file

        Returns:
            List of import statements found
        """
        language = self.parser.detect_language(file_path)
        if not language:
            return []

        # Language-specific patterns for imports
        patterns = {
            'python': '(import_statement) @import',
            'javascript': '(import_statement) @import',
            'typescript': '(import_statement) @import',
            'java': '(import_declaration) @import',
            'go': '(import_declaration) @import',
            'rust': '(use_declaration) @import',
        }

        pattern = patterns.get(language)
        if not pattern:
            return []

        return self.search_pattern(pattern, file_path, language)

    def find_string_literals(self, file_path: Path, content_filter: Optional[str] = None) -> List[SearchResult]:
        """
        Find all string literals in a file, optionally filtered by content.

        Args:
            file_path: Path to the file
            content_filter: Optional substring to filter strings by

        Returns:
            List of string literals found
        """
        language = self.parser.detect_language(file_path)
        if not language:
            return []

        # Most languages use similar string literal nodes
        pattern = '(string) @string'

        results = self.search_pattern(pattern, file_path, language)

        # Apply content filter if provided
        if content_filter:
            results = [r for r in results if content_filter in r.text]

        return results

    def find_function_calls(self, file_path: Path, function_name: Optional[str] = None) -> List[SearchResult]:
        """
        Find function calls in a file, optionally filtered by name.

        Args:
            file_path: Path to the file
            function_name: Optional function name to filter by

        Returns:
            List of function calls found
        """
        language = self.parser.detect_language(file_path)
        if not language:
            return []

        # Language-specific patterns for function calls
        patterns = {
            'python': '(call function: (identifier) @func_call)',
            'javascript': '(call_expression function: (identifier) @func_call)',
            'typescript': '(call_expression function: (identifier) @func_call)',
            'java': '(method_invocation name: (identifier) @func_call)',
            'c': '(call_expression function: (identifier) @func_call)',
            'cpp': '(call_expression function: (identifier) @func_call)',
            'go': '(call_expression function: (identifier) @func_call)',
            'rust': '(call_expression function: (identifier) @func_call)',
        }

        pattern = patterns.get(language)
        if not pattern:
            return []

        results = self.search_pattern(pattern, file_path, language)

        # Apply function name filter if provided
        if function_name:
            results = [r for r in results if function_name in r.text]

        return results

    def custom_search(
        self,
        file_path: Path,
        node_filter: Callable[[Node, bytes], bool]
    ) -> List[SearchResult]:
        """
        Perform a custom search using a filter function.

        Args:
            file_path: Path to the file
            node_filter: Function that takes a node and source code and returns True to include

        Returns:
            List of search results
        """
        root_node = self.parser.parse_file(file_path)
        if not root_node:
            return []

        with open(file_path, 'rb') as f:
            source_code = f.read()

        results = []

        def traverse(node: Node, depth: int):
            if node_filter(node, source_code):
                text = self.parser.get_node_text(node, source_code)
                result = SearchResult(
                    file_path=file_path,
                    line_number=node.start_point[0] + 1,
                    column=node.start_point[1],
                    node_type=node.type,
                    text=text,
                    context={'depth': depth},
                    captures={}
                )
                results.append(result)

        self.parser.traverse_tree(root_node, traverse)
        return results
