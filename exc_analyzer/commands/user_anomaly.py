"""Advanced user anomaly detection with risk scoring and pattern analysis."""
from ..print_utils import Print, _write_output, safe_print
from ..api import api_get, get_auth_header
from ..i18n import t
from collections import Counter
from datetime import datetime, timezone
import re
def cmd_user_anomaly(args):
    if not args.username:
        Print.error(t("commands.user_a.missing_username"))
        _write_output(f"\n{t('commands.user_anomaly.usage')}")
        return
    headers = get_auth_header()
    user = args.username.strip()
    safe_print("")
    Print.info(t("commands.user_anomaly.checking", user=user))
    safe_print("")
    from ..spinner import spinner
    with spinner(t("commands.user_anomaly.fetching_data"), color='96'):
        user_url = f"https://api.github.com/users/{user}"
        user_data, _ = api_get(user_url, headers)
        events_url = f"https://api.github.com/users/{user}/events/public?per_page=100"
        events, _ = api_get(events_url, headers)
        repos_url = f"https://api.github.com/users/{user}/repos?per_page=100"
        repos, _ = api_get(repos_url, headers)
    with spinner(t("commands.user_anomaly.analyzing"), color='93'):
        analysis = _analyze_user(user_data, events, repos)
    _print_analysis(user, analysis)
def _analyze_user(user_data, events, repos):
    """Comprehensive user analysis with anomaly detection."""
    anomalies = []
    risk_score = 0
    created_at = user_data.get('created_at', '')
    if created_at:
        account_age_days = (datetime.now(timezone.utc) - datetime.fromisoformat(created_at.replace('Z', '+00:00'))).days
        public_repos = user_data.get('public_repos', 0)
        if account_age_days < 30 and public_repos > 10:
            anomalies.append({
                'type': 'warning',
                'message': t("commands.user_anomaly.anomaly.new_account_high_activity", 
                           days=account_age_days, repos=public_repos)
            })
            risk_score += 20
        if account_age_days > 365 and public_repos == 0 and len(events) == 0:
            anomalies.append({
                'type': 'info',
                'message': t("commands.user_anomaly.anomaly.old_account_no_activity")
            })
            risk_score += 10
    followers = user_data.get('followers', 0)
    following = user_data.get('following', 0)
    if following > 0:
        ratio = followers / following
        if following > 1000 and ratio < 0.1:
            anomalies.append({
                'type': 'warning',
                'message': t("commands.user_anomaly.anomaly.suspicious_follow_ratio",
                           followers=followers, following=following)
            })
            risk_score += 25
    if repos:
        fork_count = sum(1 for r in repos if r.get('fork', False))
        fork_ratio = fork_count / len(repos) if len(repos) > 0 else 0
        if fork_ratio > 0.8 and len(repos) > 5:
            anomalies.append({
                'type': 'warning',
                'message': t("commands.user_anomaly.anomaly.high_fork_ratio",
                           ratio=int(fork_ratio * 100), forks=fork_count, total=len(repos))
            })
            risk_score += 15
    if events:
        hours = [int(e['created_at'][11:13]) for e in events if 'created_at' in e]
        hour_counts = Counter(hours)
        if hour_counts:
            most_common_hour, count = hour_counts.most_common(1)[0]
            if count > len(hours) * 0.5 and len(hours) > 10:
                anomalies.append({
                    'type': 'warning',
                    'message': t("commands.user_anomaly.anomaly.concentrated_activity",
                               count=count, hour=most_common_hour)
                })
                risk_score += 15
            night_activity = sum(hour_counts.get(h, 0) for h in range(0, 6))
            if night_activity > len(hours) * 0.7 and len(hours) > 10:
                anomalies.append({
                    'type': 'info',
                    'message': t("commands.user_anomaly.anomaly.night_activity",
                               percent=int((night_activity/len(hours))*100))
                })
                risk_score += 5
    profile_score = 0
    if user_data.get('name'): profile_score += 1
    if user_data.get('bio'): profile_score += 1
    if user_data.get('location'): profile_score += 1
    if user_data.get('email'): profile_score += 1
    if user_data.get('blog'): profile_score += 1
    if profile_score <= 1 and (followers > 100 or public_repos > 10):
        anomalies.append({
            'type': 'info',
            'message': t("commands.user_anomaly.anomaly.incomplete_profile")
        })
        risk_score += 10
    if events:
        event_types = Counter(e.get('type', 'Unknown') for e in events)
        if event_types:
            most_common_type, type_count = event_types.most_common(1)[0]
            if type_count > len(events) * 0.9 and len(events) > 20:
                anomalies.append({
                    'type': 'warning',
                    'message': t("commands.user_anomaly.anomaly.repetitive_events",
                               event_type=most_common_type, percent=int((type_count/len(events))*100))
                })
                risk_score += 20
    if events:
        push_events = [e for e in events if e.get('type') == 'PushEvent']
        if push_events:
            commit_messages = []
            for event in push_events:
                commits = event.get('payload', {}).get('commits', [])
                for commit in commits:
                    msg = commit.get('message', '')
                    if msg:
                        commit_messages.append(msg)
            if commit_messages:
                spam_patterns = ['update', 'fix', 'test', 'commit', 'change', 'modify']
                single_word_count = sum(1 for msg in commit_messages if len(msg.split()) <= 2)
                spam_word_count = sum(1 for msg in commit_messages 
                                     if any(pattern in msg.lower() for pattern in spam_patterns) 
                                     and len(msg.split()) <= 3)
                if len(commit_messages) > 10:
                    if single_word_count > len(commit_messages) * 0.7:
                        anomalies.append({
                            'type': 'warning',
                            'message': t("commands.user_anomaly.anomaly.low_quality_commits",
                                       percent=int((single_word_count/len(commit_messages))*100))
                        })
                        risk_score += 15
    if repos and len(repos) > 5:
        repo_names = [r.get('name', '') for r in repos]
        random_pattern_count = sum(1 for name in repo_names 
                                  if re.match(r'^[a-z]{8,}\d+$', name.lower()) or 
                                     re.match(r'^repo-?\d+$', name.lower()) or
                                     re.match(r'^test-?\d+$', name.lower()))
        if random_pattern_count > len(repos) * 0.5:
            anomalies.append({
                'type': 'warning',
                'message': t("commands.user_anomaly.anomaly.random_repo_names",
                           count=random_pattern_count, total=len(repos))
            })
            risk_score += 20
    if events and len(events) > 20:
        from collections import defaultdict
        events_by_day = defaultdict(int)
        for event in events:
            day = event.get('created_at', '')[:10]  
            if day:
                events_by_day[day] += 1
        if events_by_day:
            max_daily = max(events_by_day.values())
            avg_daily = sum(events_by_day.values()) / len(events_by_day)
            if max_daily > avg_daily * 5 and avg_daily > 1:
                anomalies.append({
                    'type': 'info',
                    'message': t("commands.user_anomaly.anomaly.activity_burst",
                               max_events=max_daily, avg_events=int(avg_daily))
                })
                risk_score += 10
    if repos and len(repos) > 5:
        languages = [r.get('language') for r in repos if r.get('language')]
        if languages:
            lang_counter = Counter(languages)
            most_common_lang, lang_count = lang_counter.most_common(1)[0]
            if lang_count > len(languages) * 0.9 and len(languages) > 10:
                anomalies.append({
                    'type': 'info',
                    'message': t("commands.user_anomaly.anomaly.single_language_focus",
                               language=most_common_lang, percent=int((lang_count/len(languages))*100))
                })
    if repos and len(repos) > 5:
        empty_repos = sum(1 for r in repos if r.get('size', 0) < 10)  
        if empty_repos > len(repos) * 0.7:
            anomalies.append({
                'type': 'warning',
                'message': t("commands.user_anomaly.anomaly.mostly_empty_repos",
                           empty=empty_repos, total=len(repos))
            })
            risk_score += 15
    risk_score = min(risk_score, 100)
    return {
        'user_data': user_data,
        'events': events,
        'repos': repos,
        'anomalies': anomalies,
        'risk_score': risk_score,
        'hour_counts': Counter([int(e['created_at'][11:13]) for e in events if 'created_at' in e]) if events else Counter()
    }
def _print_analysis(username, analysis):
    """Print formatted analysis results."""
    user_data = analysis['user_data']
    anomalies = analysis['anomalies']
    risk_score = analysis['risk_score']
    hour_counts = analysis['hour_counts']
    safe_print(Print.colorize("═" * 60, '96'))
    header = f"  {t('commands.user_anomaly.header', user=username)}"
    safe_print(Print.colorize(header, '1;97'))
    safe_print(Print.colorize("═" * 60, '96'))
    safe_print("")
    risk_level, risk_color = _get_risk_level(risk_score)
    score_text = f"  {t('commands.user_anomaly.risk_score')}: {risk_score}/100 ({risk_level})"
    safe_print(Print.colorize(score_text, risk_color))
    safe_print("")
    if anomalies:
        safe_print(Print.colorize(f"  {t('commands.user_anomaly.anomalies_detected')}:", '93'))
        safe_print("")
        for anomaly in anomalies:
            if anomaly['type'] == 'warning':
                Print.warn(f"  {anomaly['message']}")
            else:
                Print.info(f"  {anomaly['message']}")
        safe_print("")
    else:
        Print.success(f"  {t('commands.user_anomaly.no_anomalies')}")
        safe_print("")
    safe_print(Print.colorize(f"  {t('commands.user_anomaly.profile_summary')}:", '96'))
    safe_print("")
    created_at = user_data.get('created_at', '')
    if created_at:
        account_age_days = (datetime.now(timezone.utc) - datetime.fromisoformat(created_at.replace('Z', '+00:00'))).days
        account_age_years = account_age_days / 365
        age_str = f"{account_age_years:.1f} {t('time.years')}" if account_age_years >= 1 else f"{account_age_days} {t('time.days')}"
    else:
        age_str = t("commands.shared.unknown")
    safe_print(f"    {t('commands.user_anomaly.account_age')}: {age_str}")
    safe_print(f"    {t('commands.user_anomaly.total_repos')}: {user_data.get('public_repos', 0)}")
    safe_print(f"    {t('commands.user_anomaly.followers_following')}: {user_data.get('followers', 0)}/{user_data.get('following', 0)}")
    if analysis['repos']:
        fork_count = sum(1 for r in analysis['repos'] if r.get('fork', False))
        safe_print(f"    {t('commands.user_anomaly.fork_ratio')}: {fork_count}/{len(analysis['repos'])}")
    safe_print("")
    if hour_counts:
        safe_print(Print.colorize(f"  {t('commands.user_anomaly.activity_chart')}:", '96'))
        safe_print("")
        _print_activity_chart(hour_counts)
        safe_print("")
    safe_print(Print.colorize("═" * 60, '96'))
    safe_print("")
def _get_risk_level(score):
    """Get risk level label and color based on score."""
    if score < 30:
        return t("commands.user_anomaly.risk_low"), '92'  
    elif score < 60:
        return t("commands.user_anomaly.risk_medium"), '93'  
    else:
        return t("commands.user_anomaly.risk_high"), '91'  
def _print_activity_chart(hour_counts):
    """Print ASCII activity chart by time blocks."""
    blocks = {
        '00-06': sum(hour_counts.get(h, 0) for h in range(0, 6)),
        '06-12': sum(hour_counts.get(h, 0) for h in range(6, 12)),
        '12-18': sum(hour_counts.get(h, 0) for h in range(12, 18)),
        '18-24': sum(hour_counts.get(h, 0) for h in range(18, 24))
    }
    max_count = max(blocks.values()) if blocks.values() else 1
    bar_width = 30
    for time_range, count in blocks.items():
        bar_length = int((count / max_count) * bar_width) if max_count > 0 else 0
        bar = "█" * bar_length + "░" * (bar_width - bar_length)
        safe_print(f"    {time_range}: {bar} ({count})")
