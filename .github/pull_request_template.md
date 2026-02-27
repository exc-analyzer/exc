## Summary

Describe what changed and why.

## Type of Change

- [ ] Bug fix
- [ ] New feature
- [ ] Refactor / internal improvement
- [ ] Documentation update
- [ ] CI / tooling
- [ ] Security hardening

## Scope

- Affected area(s):
  - [ ] analysis
  - [ ] dork-scan
  - [ ] security-score
  - [ ] login/auth/keyring
  - [ ] output/reporting
  - [ ] i18n
  - [ ] docs
  - [ ] CI/devex
  - [ ] other

## Security & Privacy Checklist

- [ ] No secrets/tokens/credentials added to code, logs, or test fixtures
- [ ] Token/auth flows were reviewed (if touched)
- [ ] Input handling was reviewed for injection/path risks (if touched)
- [ ] New dependencies were reviewed for necessity and risk (if added)

## Testing Evidence

List what you ran and the result.

```text
pytest -q
# result:
```

Optional focused checks:

```text
python -m ruff check exc_analyzer --select F401,E9,F63,F7,F82
python -m bandit -r exc_analyzer -ll
```

## Backward Compatibility

- [ ] No breaking changes
- [ ] Breaking change (describe below)

If breaking:
- What breaks?
- Migration path:

## UI/Output Changes (if applicable)

Include before/after terminal output snippets or screenshots.

## Documentation

- [ ] README/docs updated (if behavior changed)
- [ ] Issue templates / release notes updated (if needed)

## Linked Issues

Closes #<issue-number>

## Maintainer Notes (optional)

Anything reviewers should pay special attention to.
