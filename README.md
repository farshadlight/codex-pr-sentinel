# 🛡️ Codex PR Sentinel

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

**Codex PR Sentinel** is an open-source, lightweight DevSecOps CLI and GitHub Action designed to help open-source maintainers automate pull request triage, static security vulnerability scanning, and AI-assisted code reviews before merging.

## ✨ Key Features

- **Automated Diff Analysis:** Parses Git diffs to identify high-risk changes, hardcoded secrets, and unsafe execution patterns.
- **AI-Ready Triage Engine:** Integrates with OpenAI models to generate structured, context-aware PR summaries, unit test suggestions, and security audits.
- **Zero-Config GitHub Action:** Drop-in workflow for instant continuous integration across Python, JavaScript, and Go repositories.
- **Deterministic Static Rules:** Fast AST and regex-based pre-checks to minimize token usage and API latency.

## 🚀 Quick Start

### Installation

```bash
pip install codex-pr-sentinel
```

Or install directly from source:

```bash
git clone https://github.com/farshadlight/codex-pr-sentinel.git
cd codex-pr-sentinel
pip install -e .
```

### CLI Usage

Analyze a local git diff before pushing:

```bash
sentinel scan --target main --output markdown
```

Run with AI-assisted deep review:

```bash
export OPENAI_API_KEY="sk-..."
sentinel review --diff-file pr_changes.diff --model gpt-4o
```

## 🔧 GitHub Actions Integration

Add the following workflow to `.github/workflows/sentinel.yml`:

```yaml
name: PR Security & Quality Triage
on: [pull_request]

jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Run Codex PR Sentinel
        uses: farshadlight/codex-pr-sentinel@v1
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

## 🗺️ Roadmap

- [x] Core static diff parser and secret detection
- [x] Modular OpenAI API integration for automated code review
- [ ] Multi-agent CVE dependency verification
- [ ] Auto-generation of patch PRs for detected vulnerabilities

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a pull request.

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.
