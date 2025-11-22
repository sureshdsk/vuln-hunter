"""Setup script for building Tree-sitter language grammars."""

import os
import sys
import subprocess
from pathlib import Path
import shutil


LANGUAGES = {
    'python': 'https://github.com/tree-sitter/tree-sitter-python',
    'javascript': 'https://github.com/tree-sitter/tree-sitter-javascript',
    'typescript': 'https://github.com/tree-sitter/tree-sitter-typescript',
    'java': 'https://github.com/tree-sitter/tree-sitter-java',
    'c': 'https://github.com/tree-sitter/tree-sitter-c',
    'cpp': 'https://github.com/tree-sitter/tree-sitter-cpp',
    'go': 'https://github.com/tree-sitter/tree-sitter-go',
    'rust': 'https://github.com/tree-sitter/tree-sitter-rust',
    'ruby': 'https://github.com/tree-sitter/tree-sitter-ruby',
    'php': 'https://github.com/tree-sitter/tree-sitter-php',
}


class TreeSitterSetup:
    """Setup Tree-sitter language grammars."""

    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.build_dir = self.base_dir / 'build'
        self.repos_dir = self.build_dir / 'repos'
        self.library_path = self.build_dir / 'languages.so'

    def setup(self):
        """Run the complete setup process."""
        print("Tree-sitter Language Grammar Setup")
        print("=" * 50)

        # Create build directories
        self.build_dir.mkdir(exist_ok=True)
        self.repos_dir.mkdir(exist_ok=True)

        # Check if already built
        if self.library_path.exists():
            print(f"\n✓ Language library already exists at {self.library_path}")
            response = input("Rebuild? (y/N): ")
            if response.lower() != 'y':
                print("Setup cancelled.")
                return

        # Clone or update repositories
        self.clone_repositories()

        # Build the language library
        self.build_library()

        print("\n" + "=" * 50)
        print("✓ Setup complete!")
        print(f"Language library: {self.library_path}")

    def clone_repositories(self):
        """Clone Tree-sitter language grammar repositories."""
        print("\n1. Cloning language grammar repositories...")

        for name, url in LANGUAGES.items():
            repo_path = self.repos_dir / f"tree-sitter-{name}"

            if repo_path.exists():
                print(f"  ✓ {name} (already exists)")
                continue

            print(f"  Cloning {name}...")
            try:
                subprocess.run(
                    ['git', 'clone', '--depth', '1', url, str(repo_path)],
                    check=True,
                    capture_output=True
                )
                print(f"  ✓ {name}")
            except subprocess.CalledProcessError as e:
                print(f"  ✗ {name} - Error: {e}")

    def build_library(self):
        """Build the shared language library using Tree-sitter CLI."""
        print("\n2. Building language library...")

        try:
            # Try using tree-sitter build command
            from tree_sitter import Language

            # Prepare language paths
            language_repos = []
            for name in LANGUAGES.keys():
                repo_path = self.repos_dir / f"tree-sitter-{name}"
                if repo_path.exists():
                    # Handle special cases
                    if name == 'typescript':
                        # TypeScript has subdirectories
                        language_repos.append((repo_path / 'typescript', 'typescript'))
                        language_repos.append((repo_path / 'tsx', 'tsx'))
                    else:
                        language_repos.append((repo_path, name))

            # Build the library
            print(f"  Building library with {len(language_repos)} languages...")

            Language.build_library(
                str(self.library_path),
                [str(path) for path, _ in language_repos]
            )

            print(f"  ✓ Library built successfully")

        except Exception as e:
            print(f"  ✗ Error building library: {e}")
            print("\nTrying alternative build method...")
            self._build_library_manual()

    def _build_library_manual(self):
        """Manual build process using compiler."""
        import platform

        system = platform.system()

        # Collect source files
        source_files = []
        include_dirs = set()

        for name in LANGUAGES.keys():
            repo_path = self.repos_dir / f"tree-sitter-{name}"
            if not repo_path.exists():
                continue

            # Find parser.c and scanner files
            src_dir = repo_path / 'src'
            if src_dir.exists():
                parser_c = src_dir / 'parser.c'
                if parser_c.exists():
                    source_files.append(str(parser_c))
                    include_dirs.add(str(src_dir))

                # Check for scanner
                for scanner in ['scanner.c', 'scanner.cc']:
                    scanner_file = src_dir / scanner
                    if scanner_file.exists():
                        source_files.append(str(scanner_file))

        # Compile command
        if system == 'Darwin':  # macOS
            compiler = 'clang'
            output_flag = '-dynamiclib'
        elif system == 'Linux':
            compiler = 'gcc'
            output_flag = '-shared'
        else:
            print(f"  ✗ Unsupported platform: {system}")
            return

        include_flags = [f"-I{dir}" for dir in include_dirs]

        compile_cmd = [
            compiler,
            output_flag,
            '-o', str(self.library_path),
            '-fPIC',
            *include_flags,
            *source_files
        ]

        print(f"  Compiling with {compiler}...")
        try:
            subprocess.run(compile_cmd, check=True, capture_output=True)
            print(f"  ✓ Library built successfully")
        except subprocess.CalledProcessError as e:
            print(f"  ✗ Compilation failed: {e.stderr.decode()}")

    def verify_installation(self):
        """Verify that the installation works."""
        print("\n3. Verifying installation...")

        if not self.library_path.exists():
            print("  ✗ Library file not found")
            return False

        try:
            from tree_sitter import Language

            # Try loading a language
            lang = Language(str(self.library_path), 'python')
            print("  ✓ Successfully loaded Python grammar")

            return True

        except Exception as e:
            print(f"  ✗ Verification failed: {e}")
            return False


def main():
    """Main entry point."""
    setup = TreeSitterSetup()

    try:
        setup.setup()

        if setup.verify_installation():
            print("\n✓ Tree-sitter setup complete and verified!")
            print("\nYou can now use the code_search module:")
            print("  from code_search import CodeParser, CodeSearcher")
        else:
            print("\n✗ Setup completed but verification failed.")
            print("You may need to install tree-sitter manually.")

    except KeyboardInterrupt:
        print("\n\nSetup cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Setup failed with error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
