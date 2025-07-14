# from .print_utils import Print

# ---------------------
# Terminal Output Helpers [tabulate]
# ---------------------

def print_table(data, headers=None):
    try:
        from tabulate import tabulate
        print(tabulate(data, headers=headers, tablefmt="fancy_grid"))
    except ImportError:
        print("Repository | File | URL")
        print("-"*60)
        for repo, path, url in data:
            print(f"{repo} | {path} | {url}")

def print_bw(label, value, use_white=True):
    color = "\033[97m" if use_white else "\033[90m"
    reset = "\033[0m"
    print(f"{color}{label:<17}: {value}{reset}")

def print_bw_list(items, formatter, use_white=True):
    for i, item in enumerate(items):
        color = "\033[97m" if (i % 2 == 0) else "\033[90m"
        reset = "\033[0m"
        print(color + formatter(item) + reset)
