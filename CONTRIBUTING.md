# Contributing

Contributions are welcome. This project is designed to be a first open source contribution: small, zero-dependency, fully tested, and easy to run.

## Five-minute quickstart

```bash
git clone https://github.com/draarivpatel-ui/python-appsec-starter.git
cd python-appsec-starter
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m appsec_starter --help
```

That is the entire setup. There is no dependency installation step.

## Pick a good first issue

Issues labeled `good first issue` are intentionally bite-sized. Each one names the exact file to change and the test to add. Comment before starting if you want confirmation that nobody else has claimed it.

## Change rules

- Keep runtime code standard-library-only.
- Preserve Python 3.9 through 3.13 compatibility.
- Add a regression test for every security fix.
- Prefer fail-closed behavior and stable machine-readable error codes.
- Never reflect attacker controlled input in errors or logs.
- Do not weaken defaults because a test payload is inconvenient. Add an explicit opt-in instead.
- Keep optional framework and `py*cage` integrations lazy.
- Keep generated build output out of commits.

## Test checklist

```bash
PYTHONPATH=src python3 -m compileall -q src tests examples scripts
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 scripts/check_dist.py dist
```

The last command is relevant after building distributions with `python3 -m build`.

## Pull requests

Keep pull requests small and explain the security tradeoff. The template in `.github/PULL_REQUEST_TEMPLATE.md` asks for the attack case, defense, tests, and compatibility impact.

## Security reports

Do not open a public issue for a suspected vulnerability. Follow [SECURITY.md](SECURITY.md).
