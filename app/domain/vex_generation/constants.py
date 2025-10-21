SKIP_DIRECTORIES = frozenset({
    ".git", "node_modules", "target", "build", "dist", "venv", ".tox",
    "__pycache__", ".mypy_cache", ".idea", ".vscode", "vendor"
})

TEXT_FILE_EXTENSIONS = frozenset({
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rs", ".php", ".rb",
    ".cs", ".cpp", ".c", ".m", ".kt", ".scala", ".swift", ".ps1", ".yml",
    ".yaml", ".toml", ".json", ".ini", ".cfg", ".gradle", ".pom", ".xml"
})
