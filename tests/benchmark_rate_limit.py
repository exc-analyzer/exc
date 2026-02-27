#!/usr/bin/env python3
"""Rate limit aware benchmark tester."""
import asyncio
import subprocess
from exc_analyzer.async_api import AsyncGitHubAPI
from exc_analyzer.config import load_key
async def get_quota():
    """Get current API quota."""
    token = load_key()
    async with AsyncGitHubAPI(token) as client:
        query = {'query': 'query { viewer { login } }', 'variables': {}}
        await client.graphql_query(query)
        return client.remaining_quota
def run_test(cmd, repo_name):
    """Run a test command and measure quota usage."""
    print(f"\n{'='*80}")
    print(f"Testing: {cmd}")
    print(f"Repository: {repo_name}")
    print('='*80)
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    for line in result.stdout.split('\n'):
        if 'Remaining requests:' in line:
            print(f"  {line.strip()}")
    print(result.stdout)
    return result.returncode
async def main():
    """Run all tests with quota tracking."""
    print("\n" + "="*80)
    print("EXC ANALYZER - RATE LIMIT AWARE BENCHMARK")
    print("="*80)
    initial_quota = await get_quota()
    print(f"\n[INFO] Starting quota: {initial_quota} requests\n")
    tests = [
        ('python -m exc_analyzer analysis google/material-design-lite', 'google/material-design-lite (small)'),
        ('python -m exc_analyzer analysis github/gitignore', 'github/gitignore (small reference)'),
        ('python -m exc_analyzer analysis nodejs/node', 'nodejs/node (large, 30K commits)'),
        ('python -m exc_analyzer analysis google/google-cloud-python', 'google/google-cloud-python'),
        ('python -m exc_analyzer analysis apache/hadoop', 'apache/hadoop (massive project)'),
    ]
    quota_history = [initial_quota]
    for cmd, repo_name in tests:
        await asyncio.sleep(1)  
        run_test(cmd, repo_name)
        current_quota = await get_quota()
        quota_used = quota_history[-1] - current_quota
        quota_history.append(current_quota)
        print(f"\n[QUOTA] Quota after test: {current_quota} remaining")
        print(f"[USED] Used in this test: {quota_used} requests")
        print(f"[TOTAL] Total used so far: {initial_quota - current_quota} requests\n")
    print("\n" + "="*80)
    print("RATE LIMIT SUMMARY")
    print("="*80)
    total_used = initial_quota - quota_history[-1]
    print(f"\nInitial quota:      {initial_quota}")
    print(f"Remaining quota:    {quota_history[-1]}")
    print(f"Total used:         {total_used} requests")
    print(f"Tests run:          {len(tests)}")
    print(f"Average per test:   {total_used // len(tests)} requests\n")
if __name__ == "__main__":
    asyncio.run(main())
