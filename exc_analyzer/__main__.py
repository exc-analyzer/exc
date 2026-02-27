"""
Entry point for running exc_analyzer as a package module.
Allows: python -m exc_analyzer <command> [args]
"""
from exc_analyzer.main import main
if __name__ == "__main__":
    main()
