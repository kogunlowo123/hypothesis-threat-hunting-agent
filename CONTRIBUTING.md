# Contributing

Thanks for helping improve this project. This guide covers the workflow and the quality bar.

## Development setup

```bash
git clone <repository-url>
cd hypothesis-threat-hunting-agent
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"
```

## Checks

Every change must pass the gates CI enforces:

```bash
make lint        # ruff check + ruff format --check
make typecheck   # mypy --strict
make cov         # pytest with a coverage gate of 80%
```

`make format` applies safe autofixes and formatting.

## Workflow

1. Open an issue for anything larger than a small fix so the design can be discussed first.
2. Branch from `main`: `feature/<short-name>` or `fix/<short-name>`.
3. Keep commits focused, with imperative subjects.
4. Add or update tests. Bug fixes need a regression test that fails without the fix.
5. Update `CHANGELOG.md` under **Unreleased** and any affected documentation.
6. Open a pull request describing the problem, the approach and how you verified it.

## Code standards

- Python 3.10+, fully type-annotated, `mypy --strict` clean.
- Docstrings explain behaviour, not restate names.
- Errors raised deliberately derive from `HuntError`.
- Hunts are pure functions of the context. No clock, network or file access.
- Redact anything that can hold a secret (command lines especially) at ingestion.
- Anything rendered into Markdown or CSV goes through `md_cell`, `md_code` or `csv_safe`.
- Never send hostnames, users, addresses or command lines to a language model.
- Every threshold is a named field in `Thresholds` with a default and a test that shows it changes the outcome.
- Tests are offline and deterministic. Use the `ev` and `make_ctx` helpers in `tests/conftest.py`.

## Adding a hunt

1. Subclass `Hunt` in the right module under `hunts/`, set `id`, `name`, `tactic`, `techniques`, `required` and
   `description`, and implement `run`, `spl` and `kql`. Add `sigma` if the logic is a pattern.
2. Build findings with `make_finding`. Include the numbers behind the decision in `details`, a plain
   `explanation`, and `benign` causes.
3. Register the hunt in `hunts/__init__.py` and add a next step to `correlate.PIVOTS`.
4. Test that it fires, that it stays quiet on similar benign data, that the allowlist and thresholds change the
   outcome, and (if it needs a baseline or configuration) that it says so through `unavailable`.
5. Add its row to the README.

## Adding a telemetry format

Write an adapter in `normalizers.py` that raises `NormalizeError` with a message that contains no record content,
register it in `NORMALIZERS`, and test it with a real sample whose sensitive values you have replaced.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Do not file public issues for vulnerabilities.

## License

By contributing you agree that your contributions are licensed under the MIT License.
