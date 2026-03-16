# /release

Release checklist before publishing to PyPI.

## Pre-release
- [ ] All tests pass: `pytest`
- [ ] No type errors: `mypy src/`
- [ ] No lint errors: `ruff check src/ tests/`
- [ ] CLAUDE.md Rules Reference is up to date
- [ ] README.md example output is current
- [ ] Version bumped in `pyproject.toml`
- [ ] `CHANGELOG.md` entry written

## Security check
- [ ] Run `/security-reviewer` on any new probe added this release
- [ ] Confirm no network calls in static probe paths
- [ ] Confirm no user code execution paths introduced

## Build & publish
```bash
hatch build
# Inspect dist/ before publishing
ls -la dist/
# Publish (requires PyPI token — enter manually)
hatch publish
```

## Post-release
- [ ] Tag release on GitHub: `git tag v<version> && git push --tags`
- [ ] Update Show HN / community posts if major release
