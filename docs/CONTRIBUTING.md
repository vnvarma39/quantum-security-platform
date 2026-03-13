# Contributing to QSIP

Thank you for your interest in contributing! Here's how to get started.

## Development Setup

```bash
git clone https://github.com/YOUR_USERNAME/quantum-security-platform.git
cd quantum-security-platform

# Frontend
npm install
npm run dev

# Backend
cd backend
python -m venv venv && source venv/bin/activate
pip install -r ../requirements-dev.txt
uvicorn main:app --reload
```

## Branching Strategy

- `main` — stable releases only
- `develop` — integration branch
- `feature/your-feature` — new features
- `fix/issue-description` — bug fixes

## Commit Convention

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add AWS Braket backend support
fix: correct QAOA qubit register allocation
docs: update quantum algorithm explanation
test: add walk probability normalisation test
refactor: extract graph risk scorer to separate module
```

## Pull Request Checklist

- [ ] Tests pass: `npm run test` and `pytest tests/ -v`
- [ ] No lint errors: `npm run lint` and `ruff check backend/`
- [ ] New features have tests
- [ ] README updated if API changed
- [ ] Conventional commit message

## Code Style

- **Python**: Black formatter (`black backend/`), Ruff linter
- **JavaScript/JSX**: Prettier (`npm run format`), ESLint

## Reporting Issues

Please include:
1. OS and Python/Node version
2. Steps to reproduce
3. Expected vs actual behaviour
4. Relevant logs

## License

By contributing, you agree your contributions will be licensed under the MIT License.
