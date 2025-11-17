@echo off
REM Development environment setup script for Windows

echo ==========================================
echo sushCore Development Environment Setup
echo ==========================================
echo.

REM Check Python version
echo Checking Python version...
python --version
echo.

REM Install dependencies
echo Installing dependencies...
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -r requirements-dev.txt
echo.

REM Setup pre-commit
echo Setting up pre-commit hooks...
pre-commit install
echo.

REM Verify tools
echo Verifying tools...
ruff --version
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Ruff not found!
    exit /b 1
)
echo.

pre-commit --version
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Pre-commit not found!
    exit /b 1
)
echo.

REM Run initial format check
echo Running initial code format check...
ruff format .
if %ERRORLEVEL% EQU 0 (
    echo Code formatted successfully
) else (
    echo Warning: Formatting issues found (this is normal for first run)
)
echo.

echo ==========================================
echo Development environment setup complete!
echo ==========================================
echo.
echo Useful commands:
echo   make help          - Show all available commands
echo   make format        - Format code
echo   make lint          - Check code quality
echo   make lint-fix      - Auto-fix linting issues
echo   make ci-local      - Run all CI checks locally
echo   make test          - Run tests
echo.

