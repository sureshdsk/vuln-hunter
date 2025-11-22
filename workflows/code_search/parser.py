"""Tree-sitter parser for multiple programming languages."""

import os
from pathlib import Path
from typing import Optional, Dict, Any
import tree_sitter
from tree_sitter import Language, Parser, Node


class CodeParser:
    """Multi-language code parser using Tree-sitter."""

    LANGUAGE_EXTENSIONS = {
        '.py': 'python',
        '.js': 'javascript',
        '.ts': 'typescript',
        '.tsx': 'typescript',
        '.jsx': 'javascript',
        '.java': 'java',
        '.c': 'c',
        '.cpp': 'cpp',
        '.cc': 'cpp',
        '.cxx': 'cpp',
        '.h': 'c',
        '.hpp': 'cpp',
        '.go': 'go',
        '.rs': 'rust',
        '.rb': 'ruby',
        '.php': 'php',
        '.cs': 'c_sharp',
        '.swift': 'swift',
        '.kt': 'kotlin',
    }

    def __init__(self, library_path: Optional[Path] = None):
        """
        Initialize the code parser.

        Args:
            library_path: Path to compiled tree-sitter languages library.
                         If None, will use the default path.
        """
        self.library_path = library_path or self._get_default_library_path()
        self.parsers: Dict[str, Parser] = {}
        self.languages: Dict[str, Language] = {}

    def _get_default_library_path(self) -> Path:
        """Get the default library path for tree-sitter languages."""
        # For now, return a path where we'll build the languages
        return Path(__file__).parent / "build" / "languages.so"

    def _ensure_language_loaded(self, language: str) -> None:
        """
        Ensure a language is loaded and parser is initialized.

        Args:
            language: Language name (e.g., 'python', 'javascript')
        """
        if language not in self.languages:
            try:
                # Try to load the language from the compiled library
                self.languages[language] = Language(str(self.library_path), language)
            except Exception as e:
                raise ValueError(
                    f"Failed to load language '{language}'. "
                    f"Make sure tree-sitter grammars are compiled. Error: {e}"
                )

        if language not in self.parsers:
            parser = Parser()
            parser.set_language(self.languages[language])
            self.parsers[language] = parser

    def parse_file(self, file_path: Path) -> Optional[Node]:
        """
        Parse a source code file.

        Args:
            file_path: Path to the source file

        Returns:
            Tree-sitter syntax tree root node, or None if parsing failed
        """
        language = self.detect_language(file_path)
        if not language:
            return None

        try:
            with open(file_path, 'rb') as f:
                code = f.read()
            return self.parse_code(code, language)
        except Exception as e:
            print(f"Error parsing file {file_path}: {e}")
            return None

    def parse_code(self, code: bytes, language: str) -> Optional[Node]:
        """
        Parse source code string.

        Args:
            code: Source code as bytes
            language: Programming language name

        Returns:
            Tree-sitter syntax tree root node, or None if parsing failed
        """
        try:
            self._ensure_language_loaded(language)
            tree = self.parsers[language].parse(code)
            return tree.root_node
        except Exception as e:
            print(f"Error parsing code in {language}: {e}")
            return None

    def detect_language(self, file_path: Path) -> Optional[str]:
        """
        Detect programming language from file extension.

        Args:
            file_path: Path to the source file

        Returns:
            Language name, or None if not supported
        """
        ext = file_path.suffix.lower()
        return self.LANGUAGE_EXTENSIONS.get(ext)

    def get_node_text(self, node: Node, source_code: bytes) -> str:
        """
        Extract text content from a tree-sitter node.

        Args:
            node: Tree-sitter node
            source_code: Original source code as bytes

        Returns:
            Text content of the node
        """
        return source_code[node.start_byte:node.end_byte].decode('utf-8', errors='ignore')

    def traverse_tree(self, node: Node, callback, depth: int = 0):
        """
        Traverse the syntax tree and apply callback to each node.

        Args:
            node: Current tree-sitter node
            callback: Function to call for each node (receives node and depth)
            depth: Current depth in the tree
        """
        callback(node, depth)
        for child in node.children:
            self.traverse_tree(child, callback, depth + 1)

    def get_node_at_position(self, root: Node, line: int, column: int) -> Optional[Node]:
        """
        Find the deepest node at a specific position.

        Args:
            root: Root node of the syntax tree
            line: Line number (0-indexed)
            column: Column number (0-indexed)

        Returns:
            Node at the position, or None
        """
        def find_node(node: Node) -> Optional[Node]:
            if not (node.start_point[0] <= line <= node.end_point[0]):
                return None

            for child in node.children:
                result = find_node(child)
                if result:
                    return result

            return node

        return find_node(root)
