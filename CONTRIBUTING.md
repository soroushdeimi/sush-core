# Contributing to sushCore

Thank you for your interest in contributing to sushCore! This document provides guidelines and instructions for contributing.

## Code of Conduct

Please be respectful and constructive in all interactions. We welcome contributors of all backgrounds and experience levels.

## Getting Started

### Prerequisites

- Python 3.9 or higher
- Git
- A virtual environment manager (venv, conda, etc.)

### Development Setup

1. **Fork and clone the repository:**
   ```bash
   git clone https://github.com/soroushdeimi/sush-core.git
   cd sush-core
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   pip install -e .
   ```

4. **Verify your setup:**
   ```bash
   python tests/test_smoke.py
   ```

## Development Workflow

### Branching Strategy

- `main` - Production-ready code
- `develop` - Integration branch for features
- `feature/*` - New features
- `fix/*` - Bug fixes
- `hotfix/*` - Critical production fixes

### Making Changes

1. Create a new branch from `develop`:
   ```bash
   git checkout develop
   git pull origin develop
   git checkout -b feature/your-feature-name
   ```

2. Make your changes following our coding standards (see below).

3. Run tests and linting:
   ```bash
   # Run tests
   python run_tests.py
   
   # Check linting
   ruff check .
   
   # Format code
   ruff format .
   ```

4. Commit your changes with clear messages:
   ```bash
   git add .
   git commit -m "feat: add quantum-resistant feature X"
   ```

5. Push and create a Pull Request:
   ```bash
   git push origin feature/your-feature-name
   ```

## Coding Standards

### Python Style

- Follow PEP 8 guidelines
- Use type hints for function signatures
- Maximum line length: 100 characters
- Use `ruff` for linting and formatting

### Code Quality

- Write docstrings for all public functions and classes
- Keep functions focused and single-purpose (SOLID principles)
- Avoid deep nesting (max 3-4 levels)
- Use meaningful variable and function names

### Security Guidelines

This is a security-critical project. Please follow these guidelines:

1. **No hardcoded secrets** - Use environment variables
2. **Input validation** - Validate all external inputs
3. **Cryptography** - Use established libraries (cryptography, pynacl)
4. **Dependencies** - Only add dependencies from trusted sources
5. **Error handling** - Don't expose sensitive information in errors

### Commit Message Format

We use conventional commits:

- `feat:` - New features
- `fix:` - Bug fixes
- `docs:` - Documentation changes
- `style:` - Code style changes (formatting)
- `refactor:` - Code refactoring
- `test:` - Adding or updating tests
- `chore:` - Maintenance tasks
- `security:` - Security-related changes

## Testing

### Running Tests

```bash
# Smoke tests (quick verification)
python tests/test_smoke.py

# Full test suite
python run_tests.py

# Individual test files
python tests/test_core_components.py
python tests/test_integration.py
```

### Writing Tests

- Place tests in the `tests/` directory
- Name test files with `test_` prefix
- Test both success and failure cases
- Mock external dependencies

## Pull Request Process

1. Ensure all tests pass
2. Ensure linting passes (`ruff check .`)
3. Update documentation if needed
4. Fill out the PR template completely
5. Request review from maintainers

### PR Checklist

- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] Linting passes
- [ ] No security vulnerabilities introduced
- [ ] Commit messages follow convention

## Security Vulnerabilities

If you discover a security vulnerability, please **do not** create a public issue. Instead:

1. Email the security team directly (see SECURITY.md)
2. Include a detailed description
3. Allow time for a fix before public disclosure

## Questions?

- Open a GitHub Issue for bugs or feature requests
- Check existing issues before creating new ones

Thank you for contributing to sushCore!
