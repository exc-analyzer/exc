import sys
from exc_analyzer.print_utils import Print
def main():
    try:
        from exc_analyzer.cli import main_cli
        main_cli()
    except Exception as e:
        try:
            from exc_analyzer.errors import ExcAnalyzerError
            if isinstance(e, ExcAnalyzerError):
                Print.error(str(e))
            else:
                from exc_analyzer.i18n import t
                Print.error(t("commands.shared.fatal_error", error=e))
        except Exception:
            Print.critical_error(f"Fatal error: {e}")
        sys.exit(1)
if __name__ == "__main__":
    main()
