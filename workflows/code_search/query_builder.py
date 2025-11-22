"""Query builder for constructing Tree-sitter queries programmatically."""

from typing import List, Optional, Dict, Any


class QueryBuilder:
    """Builder for constructing Tree-sitter query patterns."""

    def __init__(self):
        """Initialize the query builder."""
        self.patterns: List[str] = []
        self.predicates: List[str] = []

    def node(self, node_type: str, **kwargs) -> 'QueryBuilder':
        """
        Add a node pattern.

        Args:
            node_type: Type of the node (e.g., 'function_definition')
            **kwargs: Named children with optional captures

        Returns:
            Self for method chaining

        Example:
            builder.node('function_definition', name='(identifier) @func_name')
        """
        parts = [node_type]
        for key, value in kwargs.items():
            parts.append(f"{key}: {value}")

        pattern = f"({' '.join(parts)})"
        self.patterns.append(pattern)
        return self

    def capture(self, name: str) -> str:
        """
        Create a capture annotation.

        Args:
            name: Name of the capture

        Returns:
            Capture annotation string

        Example:
            builder.capture('func_name') -> '@func_name'
        """
        return f"@{name}"

    def any_of(self, *patterns: str) -> str:
        """
        Create an alternation pattern (matches any of the patterns).

        Args:
            *patterns: Patterns to match

        Returns:
            Alternation pattern

        Example:
            builder.any_of('identifier', 'attribute')
        """
        return f"[{' '.join(patterns)}]"

    def wildcard(self) -> str:
        """
        Create a wildcard pattern that matches any node.

        Returns:
            Wildcard pattern
        """
        return "(_)"

    def match_predicate(self, capture: str, regex: str) -> 'QueryBuilder':
        """
        Add a match predicate to filter captures by regex.

        Args:
            capture: Name of the capture to filter
            regex: Regular expression pattern

        Returns:
            Self for method chaining

        Example:
            builder.match_predicate('func_name', '^test_')
        """
        self.predicates.append(f'(#match? @{capture} "{regex}")')
        return self

    def eq_predicate(self, capture: str, value: str) -> 'QueryBuilder':
        """
        Add an equality predicate to filter captures.

        Args:
            capture: Name of the capture to filter
            value: Value to match exactly

        Returns:
            Self for method chaining

        Example:
            builder.eq_predicate('method', 'execute')
        """
        self.predicates.append(f'(#eq? @{capture} "{value}")')
        return self

    def not_eq_predicate(self, capture: str, value: str) -> 'QueryBuilder':
        """
        Add a not-equal predicate to filter captures.

        Args:
            capture: Name of the capture to filter
            value: Value to not match

        Returns:
            Self for method chaining
        """
        self.predicates.append(f'(#not-eq? @{capture} "{value}")')
        return self

    def build(self) -> str:
        """
        Build the final query string.

        Returns:
            Complete Tree-sitter query pattern
        """
        query_parts = self.patterns + self.predicates
        return '\n'.join(query_parts)

    @staticmethod
    def function_with_name(func_name: str, language: str = 'python') -> str:
        """
        Build a query to find functions with a specific name.

        Args:
            func_name: Name of the function to find
            language: Programming language

        Returns:
            Query pattern
        """
        builders = {
            'python': lambda: QueryBuilder()
                .node('function_definition', name='(identifier) @func_name')
                .eq_predicate('func_name', func_name),
            'javascript': lambda: QueryBuilder()
                .node('function_declaration', name='(identifier) @func_name')
                .eq_predicate('func_name', func_name),
        }

        builder = builders.get(language, builders['python'])
        return builder().build()

    @staticmethod
    def class_with_name(class_name: str, language: str = 'python') -> str:
        """
        Build a query to find classes with a specific name.

        Args:
            class_name: Name of the class to find
            language: Programming language

        Returns:
            Query pattern
        """
        builders = {
            'python': lambda: QueryBuilder()
                .node('class_definition', name='(identifier) @class_name')
                .eq_predicate('class_name', class_name),
            'javascript': lambda: QueryBuilder()
                .node('class_declaration', name='(identifier) @class_name')
                .eq_predicate('class_name', class_name),
        }

        builder = builders.get(language, builders['python'])
        return builder().build()

    @staticmethod
    def imports_from_module(module_name: str, language: str = 'python') -> str:
        """
        Build a query to find imports from a specific module.

        Args:
            module_name: Name of the module
            language: Programming language

        Returns:
            Query pattern
        """
        if language == 'python':
            return f"""
            (import_from_statement
              module_name: (dotted_name) @module)
            (#eq? @module "{module_name}")
            """
        elif language == 'javascript':
            return f"""
            (import_statement
              source: (string) @module)
            (#match? @module ".*{module_name}.*")
            """
        return ""

    @staticmethod
    def function_calls_to(func_name: str, language: str = 'python') -> str:
        """
        Build a query to find calls to a specific function.

        Args:
            func_name: Name of the function being called
            language: Programming language

        Returns:
            Query pattern
        """
        builders = {
            'python': lambda: QueryBuilder()
                .node('call', function='(identifier) @func_name')
                .eq_predicate('func_name', func_name),
            'javascript': lambda: QueryBuilder()
                .node('call_expression', function='(identifier) @func_name')
                .eq_predicate('func_name', func_name),
        }

        builder = builders.get(language, builders['python'])
        return builder().build()

    @staticmethod
    def string_containing(substring: str) -> str:
        """
        Build a query to find string literals containing a substring.

        Args:
            substring: Substring to search for

        Returns:
            Query pattern
        """
        return f"""
        (string) @str
        (#match? @str ".*{substring}.*")
        """

    @staticmethod
    def decorators_with_name(decorator_name: str, language: str = 'python') -> str:
        """
        Build a query to find decorators with a specific name.

        Args:
            decorator_name: Name of the decorator
            language: Programming language

        Returns:
            Query pattern
        """
        if language == 'python':
            return f"""
            (decorator
              (identifier) @decorator)
            (#eq? @decorator "{decorator_name}")
            """
        return ""

    @staticmethod
    def variable_assignments(var_name: Optional[str] = None, language: str = 'python') -> str:
        """
        Build a query to find variable assignments.

        Args:
            var_name: Optional variable name to filter
            language: Programming language

        Returns:
            Query pattern
        """
        builder = QueryBuilder()

        if language == 'python':
            builder.node('assignment', left='(identifier) @var_name', right='(_) @value')
        elif language == 'javascript':
            builder.node('variable_declarator', name='(identifier) @var_name', value='(_) @value')

        if var_name:
            builder.eq_predicate('var_name', var_name)

        return builder.build()

    @staticmethod
    def comments_containing(text: str) -> str:
        """
        Build a query to find comments containing specific text.

        Args:
            text: Text to search for in comments

        Returns:
            Query pattern
        """
        return f"""
        (comment) @comment
        (#match? @comment ".*{text}.*")
        """
