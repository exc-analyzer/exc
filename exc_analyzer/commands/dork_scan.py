import requests
import re
import csv
import json
import time
import math
from collections import Counter
from urllib.parse import quote, unquote
from ..print_utils import Print, _write_output
from ..api import api_get, get_auth_header
from ..i18n import t
from .dork_presets import PRESETS, get_preset_choices
from ..helpers import TablePrinter, _truncate, truncate_visual, get_visual_width
def cmd_dork_scan(args):
    if args.list_presets:
        _list_presets()
        return
    queries = []
    if args.query:
        queries.extend(args.query)
    if args.preset:
        if args.preset in PRESETS:
            queries.extend(PRESETS[args.preset])
        else:
            Print.error(t("commands.dork_scan.invalid_preset", preset=args.preset))
            return
    if not queries:
         Print.error(t("commands.shared.missing_query"))
         return
    headers = get_auth_header()
    num = args.num or 10
    if num > 100:
        num = 100
    full_query_str = " ".join(queries) 
    display_query = _truncate(full_query_str, 50)
    Print.info(t("commands.dork_scan.searching", query=display_query, num=num))
    _write_output("")
    search_term = ""
    processed_queries = [_smart_quote_query(q) for q in queries]
    if args.preset:
        search_term = " OR ".join(processed_queries)
    else:
        search_term = " ".join(processed_queries)
    if len(search_term) > 256:
        Print.warn(t("commands.dork_scan.long_query_warning"))
    from ..spinner import spinner
    url = f"https://api.github.com/search/code?q={quote(search_term)}&per_page={num}"
    data = {}
    with spinner(t("commands.dork_scan.searching_spinner"), color='96'):
        try:
            data, _ = api_get(url, headers)
        except Exception as e:
            Print.error(str(e))
            return
    items = data.get('items', [])
    if not items:
        Print.warn(t("commands.dork_scan.none_found"))
        return
    results = []
    if args.verify:
        Print.info(t("commands.dork_scan.verifying_count", count=len(items)))
        with spinner(t("commands.dork_scan.verifying_spinner"), color='93'):
            for item in items:
                status, severity = _verify_content(item, headers)
                results.append({
                    'repo': item['repository']['full_name'],
                    'path': item['path'],
                    'url': item['html_url'],
                    'status': status,
                    'severity': severity
                })
                time.sleep(0.1)
        clean_results = [r for r in results if r.get('severity', 0) == 0]
        risky_results = [r for r in results if r.get('severity', 0) > 0]
        risky_results.sort(key=lambda x: x['severity'], reverse=True)
        filtered_count = len(clean_results)
        final_results = risky_results
    else:
        for item in items:
            results.append({
                'repo': item['repository']['full_name'],
                'path': item['path'],
                'url': item['html_url'],
                'status': t("commands.dork_scan.status.unverified"),
                'severity': 0 
            })
        final_results = results
        filtered_count = 0
    _print_results(final_results, verify_enabled=args.verify)
    if filtered_count > 0:
        Print.info(t("commands.dork_scan.filtered_count", count=filtered_count))
    if args.export:
        _export_results(results, args.export)
def _verify_content(item, headers):
    """
    Fetch file content and check for obvious patterns.
    This is a 'lite' verification.
    """
    try:
        html_url = item.get('html_url', '')
        if 'github.com' in html_url and '/blob/' in html_url:
            raw_url = html_url.replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')
            resp = requests.get(raw_url)
            if resp.status_code == 200:
                content = resp.text
                return _analyze_content(content)
    except Exception:
        pass
    return t("commands.dork_scan.status.check_failed"), 0
def _analyze_content(content):
    """
    Context-aware content analysis with false positive reduction.
    Returns (verification_status, severity_score)
    Severity: 3 (High/Verified), 2 (Suspicious), 1 (Potential), 0 (Clean/Safe)
    """
    lower_content = content.lower()
    example_indicators = [
        'example', 'sample', 'demo', 'test', 'placeholder', 'dummy',
        'fake', 'mock', 'your_key_here', 'replace_with', 'insert_here',
        'todo', 'fixme', 'xxx', 'yyy', 'zzz', '12345', 'abcdef'
    ]
    doc_indicators = ['readme', 'example', '.md', 'documentation', 'tutorial', 'guide']
    is_likely_doc = any(ind in lower_content[:500] for ind in doc_indicators)
    secret_patterns = {
        'AWS Access Key': r'(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])',
        'AWS Secret Key': r'(?i)aws.{0,20}secret.{0,20}[\'"][0-9a-zA-Z/+=]{40}[\'"]',
        'GitHub Token (Classic)': r'ghp_[a-zA-Z0-9]{36}',
        'GitHub Token (Fine-grained)': r'github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}',
        'Slack Token': r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}',
        'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
        'Stripe Secret Key': r'sk_live_[0-9a-zA-Z]{24,}',
        'Private Key Header': r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
        'Generic High-Value Secret': r'(?i)(api[_-]?key|secret[_-]?key|auth[_-]?token|access[_-]?token)\s*[:=]\s*[\'"][A-Za-z0-9_\-/+=]{16,}[\'"]'
    }
    for secret_type, pattern in secret_patterns.items():
        matches = list(re.finditer(pattern, content))
        for match in matches:
            matched_text = match.group(0)
            start = max(0, match.start() - 100)
            end = min(len(content), match.end() + 100)
            context = content[start:end]
            if _is_likely_example_or_comment(context, matched_text, example_indicators):
                continue
            if secret_type in ['AWS Access Key', 'GitHub Token (Classic)', 'GitHub Token (Fine-grained)']:
                if _calculate_entropy(matched_text) < 3.5:
                    continue  
            return f"{t('commands.dork_scan.status.verified')} ({secret_type})", 3
    suspicious_patterns = [
        r'password\s*[:=]\s*[\'"][^\'"]{8,}[\'"]',
        r'token\s*[:=]\s*[\'"][^\'"]{20,}[\'"]',
        r'-----BEGIN .+ PRIVATE KEY-----'
    ]
    for pat in suspicious_patterns:
        if re.search(pat, content, re.IGNORECASE):
            matches = list(re.finditer(pat, content, re.IGNORECASE))
            for match in matches:
                start = max(0, match.start() - 100)
                end = min(len(content), match.end() + 100)
                context = content[start:end]
                if not _is_likely_example_or_comment(context, match.group(0), example_indicators):
                    return t("commands.dork_scan.status.suspicious"), 2
    if len(content) < 50:
        return t("commands.dork_scan.status.suspicious_small"), 1
    if is_likely_doc:
        return t("commands.dork_scan.status.likely_example"), 1
    return t("commands.dork_scan.status.no_secrets"), 0
def _is_likely_example_or_comment(context, matched_text, example_indicators):
    """Check if the match is likely in an example or comment."""
    context_lower = context.lower()
    for indicator in example_indicators:
        if indicator in context_lower:
            return True
    lines = context.split('\n')
    for line in lines:
        if matched_text in line:
            stripped = line.strip()
            if stripped.startswith('#'):
                return True
            if stripped.startswith('//') or '/*' in line or '*/' in line:
                return True
            if '<!--' in line or '-->' in line:
                return True
    return False
def _calculate_entropy(text):
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0
    counter = Counter(text)
    length = len(text)
    entropy = 0
    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy
def _print_results(results, verify_enabled=False):
    columns = [
        {'header': t("commands.dork_scan.table_header.repo"), 'width': 25, 'color': '94'},
        {'header': t("commands.dork_scan.table_header.file"), 'width': None, 'color': '97'}, 
        {'header': t("commands.dork_scan.table_header.link"), 'width': 35, 'color': '33'}
    ]
    if verify_enabled:
        columns.append({'header': t("commands.dork_scan.table_header.status"), 'width': 20, 'color': '92'})
    safe_print("")
    printer = TablePrinter(columns)
    printer.print_header()
    w_repo = columns[0]['_actual_width']
    w_file = columns[1]['_actual_width']
    w_link = columns[2]['_actual_width']
    w_stat = columns[3]['_actual_width'] if verify_enabled else 0
    for i, res in enumerate(results):
        display_repo = _truncate(res['repo'], w_repo)
        display_file = smart_truncate_path(res['path'], w_file)
        display_link = shorten_display_url(res['url'], w_link)
        row = [display_repo, display_file, (display_link, res['url'])]
        if verify_enabled:
            row.append(_truncate(res['status'], w_stat))
        style = "2;" if i % 2 == 1 else ""
        printer.print_row(row, style_prefix=style)
    safe_print("")
    Print.info(t("commands.dork_scan.total", count=len(results)))
    Print.warn(t("commands.dork_scan.disclaimer"))
    safe_print("")
def _export_results(results, filepath):
    """Export results to JSON or CSV"""
    try:
        if filepath.lower().endswith('.json'):
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
        else:
            if not filepath.lower().endswith('.csv'):
                filepath += '.csv'
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                header = ['Repository', 'Path', 'URL', 'Status']
                writer.writerow(header)
                for r in results:
                    writer.writerow([r['repo'], r['path'], r['url'], r['status']])
        Print.success(t("commands.dork_scan.export_success", path=filepath))
    except Exception as e:
        Print.error(t("commands.dork_scan.export_error", error=str(e)))
def _list_presets():
    Print.info(t("commands.dork_scan.presets_list_header"))
    for k, v in PRESETS.items():
        examples = ", ".join(v[:3])
        if len(v) > 3:
            examples += "..."
        print(f"  - {k:<10} : {examples}")
    print()
def shorten_display_url(full_url, max_len):
    try:
       full_url = unquote(full_url)
    except:
       pass
    if "/blob/" not in full_url:
        return _truncate(full_url, max_len)
    try:
        parts = full_url.split("/blob/")
        rest = parts[1]
        sha_parts = rest.split("/", 1)
        filename = sha_parts[1].split("/")[-1] if len(sha_parts) > 1 else "file"
        prefix = "github.com/.../"
        available = max_len - len(prefix)
        if len(filename) > available:
            filename = _truncate(filename, available)
        return f"{prefix}{filename}"
    except:
         return _truncate(full_url, max_len)
def smart_truncate_path(path, max_width):
    """Truncate path with priority to filename"""
    visual_len = get_visual_width(path)
    if visual_len <= max_width:
        return path
    parts = path.split('/')
    if len(parts) > 1:
        filename = parts[-1]
        fn_len = get_visual_width(filename)
        if fn_len >= max_width:
             return truncate_visual(filename, max_width)
        rem = max_width - fn_len - 4 
        if rem > 3:
            folder = parts[0]
            truncated_folder = truncate_visual(folder, rem)
            return f"{truncated_folder}/.../{filename}"
        else:
            return f".../{filename}"
    return truncate_visual(path, max_width)
def _smart_quote_query(query):
    """
    Intelligently quote the query if it contains spaces but no search modifiers.
    Enables logic like:
    - Linus Torvalds -> "Linus Torvalds" (Exact match)
    - filename:test.py -> filename:test.py (Modifier, no quote)
    - repo:x error -> repo:x error (Contains modifier, no quote)
    """
    if query.startswith('"') and query.endswith('"'):
        return query
    if " " not in query:
        return query
    modifiers = [
        'repo', 'user', 'org', 'path', 'filename', 'extension', 
        'size', 'pushed', 'created', 'language', 'topic', 
        'license', 'followers', 'fork', 'stars', 'is'
    ]
    for mod in modifiers:
        if f"{mod}:" in query:
            return query
    return f'"{query}"'
def safe_print(msg=""):
    print(msg)
    _write_output(msg)
