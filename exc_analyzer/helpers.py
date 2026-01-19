def format_size(bytes_count):
    """Format byte count to human-readable size (KB, MB, GB)."""
    if bytes_count < 1024:
        return f"{bytes_count} bytes"
    elif bytes_count < 1024 * 1024:
        kb = bytes_count / 1024
        return f"{kb:.1f} KB"
    elif bytes_count < 1024 * 1024 * 1024:
        mb = bytes_count / (1024 * 1024)
        return f"{mb:.1f} MB"
    else:
        gb = bytes_count / (1024 * 1024 * 1024)
        return f"{gb:.1f} GB"
def format_friendly_date(date_str, include_relative=False):
    """Format ISO date string to a friendly format (e.g. 22 Sep 2024)."""
    from datetime import datetime, timezone
    from .i18n import get_active_language, t
    if not date_str:
        return ""
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return date_str
    lang = get_active_language()
    date_text = ""
    if lang == "tr":
        months = [
            "", "Ocak", "Şubat", "Mart", "Nisan", "Mayıs", "Haziran",
            "Temmuz", "Ağustos", "Eylül", "Ekim", "Kasım", "Aralık"
        ]
        date_text = f"{dt.day} {months[dt.month]} {dt.year}"
    else:
        date_text = dt.strftime("%d %b %Y")
    if include_relative:
        rel_text = _get_relative_time(dt)
        return f"{date_text} ({rel_text})"
    return date_text
def _get_relative_time(dt):
    """Calculate relative time string (e.g. 2 years ago)."""
    from datetime import datetime, timezone
    from .i18n import t
    now = datetime.now(timezone.utc)
    diff = now - dt
    seconds = diff.total_seconds()
    if seconds < 0:
        return t("time.just_now") 
    if seconds < 60:
        return t("time.just_now")
    minutes = int(seconds / 60)
    if minutes < 60:
        return f"{minutes} {t('time.minutes' if minutes > 1 else 'time.minute')} {t('time.ago')}"
    hours = int(minutes / 60)
    if hours < 24:
        return f"{hours} {t('time.hours' if hours > 1 else 'time.hour')} {t('time.ago')}"
    days = int(hours / 24)
    if days < 30:
        return f"{days} {t('time.days' if days > 1 else 'time.day')} {t('time.ago')}"
    months = int(days / 30)
    if months < 12:
        return f"{months} {t('time.months' if months > 1 else 'time.month')} {t('time.ago')}"
    years = int(months / 12)
    return f"{years} {t('time.years' if years > 1 else 'time.year')} {t('time.ago')}"
def _truncate(text, width):
    """Truncate text to fit width, adding ellipsis if needed."""
    return truncate_visual(text, width)
def get_visual_width(text):
    """Calculate visual width of string (handling CJK wide chars)."""
    import unicodedata
    w = 0
    for char in str(text):
        cw = unicodedata.east_asian_width(char)
        w += 2 if cw in ('W', 'F') else 1
    return w
def truncate_visual(text, max_width):
    """Truncate string to max_visual_width, adding ... if needed."""
    if not text:
        return ""
    text = str(text)
    current_width = 0
    result = []
    if get_visual_width(text) <= max_width:
        return text
    target_width = max_width - 3 if max_width > 3 else max_width
    for char in text:
        import unicodedata
        cw = unicodedata.east_asian_width(char)
        char_width = 2 if cw in ('W', 'F') else 1
        if current_width + char_width > target_width:
            break
        result.append(char)
        current_width += char_width
    return "".join(result) + "..."
def pad_visual(text, width):
    """Pad string with spaces to reach visual width."""
    v_width = get_visual_width(text)
    padding = width - v_width
    if padding < 0:
        return text 
    return text + (" " * padding)
class TablePrinter:
    """
    Centralized table printing logic with visual width support and dynamic sizing.
    Handles both colored terminal output and clean file output.
    """
    def __init__(self, columns, terminal_width=None):
        """
        Initialize table with column definitions.
        Args:
            columns: List of dicts with keys:
                - header: str (Title)
                - width: int (Fixed width) or None (Flex)
                - color: str (Color code, e.g. '96')
                - align: str ('left', 'right') [default: left]
            terminal_width: Optional manual width override
        """
        import shutil
        self.columns = columns
        self.term_width = terminal_width or shutil.get_terminal_size((100, 20)).columns
        self._calculate_widths()
    def _calculate_widths(self):
        """Calculate actual widths for flex columns."""
        fixed_width = sum(c.get('width', 0) for c in self.columns if c.get('width'))
        gap_size = 2
        total_gaps = (len(self.columns) - 1) * gap_size
        available = self.term_width - fixed_width - total_gaps
        flex_cols = [c for c in self.columns if not c.get('width')]
        if flex_cols:
            flex_width = max(10, available // len(flex_cols))
            for col in flex_cols:
                col['_actual_width'] = flex_width
        for col in self.columns:
            if col.get('width'):
                col['_actual_width'] = col['width']
    def print_header(self):
        """Print the table header."""
        from .print_utils import Print, _write_output, safe_print
        parts_colored = []
        parts_plain = []
        for col in self.columns:
            w = col['_actual_width']
            h = col.get('header', '').upper()
            padded = pad_visual(h, w)
            parts_plain.append(padded)
            parts_colored.append(Print.colorize(padded, '1;97'))
        line_colored = "  ".join(parts_colored)
        line_plain = "   ".join(parts_plain) 
        try:
            print(line_colored)
        except:
            pass
        _write_output(line_plain)
        self.print_separator()
    def print_separator(self):
        """Print dashed separator line."""
        from .print_utils import Print, _write_output, safe_print
        parts = []
        for col in self.columns:
            w = col['_actual_width']
            parts.append("-" * w)
        sep = "  ".join(parts)
        print(Print.colorize(sep, '90'))
        _write_output("   ".join(["-" * col['_actual_width'] for col in self.columns]))
    def print_row(self, data, color_override=None, style_prefix=""):
        """
        Print a single row of data.
        Args:
            data: List of values corresponding to columns.
            color_override: Optional generic color for the whole row (e.g. for dimming).
            style_prefix: Optional ANSI style prefix (e.g. '2;' for dim), prepended to color.
        """
        from .print_utils import Print, _write_output, COLOR_ENABLED
        parts_screen = []
        parts_file = []
        for idx, col in enumerate(self.columns):
            raw_val = data[idx] if idx < len(data) else ""
            w = col['_actual_width']
            url = None
            if isinstance(raw_val, tuple):
                val_text = str(raw_val[0])
                url = str(raw_val[1])
            else:
                val_text = str(raw_val)
            base_color = color_override or col.get('color', '97')
            final_color = f"{style_prefix}{base_color}" if style_prefix else base_color
            truncated = truncate_visual(val_text, w)
            padded = pad_visual(truncated, w)
            colored_text = Print.colorize(padded, final_color)
            if url and COLOR_ENABLED:
                hyperlinked = f"\033]8;;{url}\033\\{colored_text}\033]8;;\033\\"
                parts_screen.append(hyperlinked)
            else:
                parts_screen.append(colored_text)
            file_val = url if url else val_text
            v_width = get_visual_width(file_val)
            padding = w - v_width
            if padding > 0:
                file_padded = file_val + (" " * padding)
            else:
                file_padded = file_val 
            parts_file.append(file_padded)
        try:
            print("  ".join(parts_screen))
        except UnicodeEncodeError:
             print("  ".join(parts_screen).encode('utf-8', errors='replace').decode('utf-8'))
        _write_output("   ".join(parts_file))
def print_bw(label, value, use_white=True):
    from .print_utils import _write_output, safe_print, Print
    color = '97' if use_white else '90'
    label_padded = f"{label:<17}"
    line = f"{Print.colorize(label_padded, color)}: {value}"
    safe_print(line)
def print_bw_list(items, formatter, use_white=True):
    from .print_utils import _write_output, safe_print, Print
    for i, item in enumerate(items):
        color = '97' if (i % 2 == 0) else '90'
        formatted = formatter(item)
        safe_print(Print.colorize(formatted, color))
