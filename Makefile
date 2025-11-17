.PHONY: help install install-dev format lint lint-fix check test clean ci-local

help: ## نمایش راهنمای دستورات
	@echo "sushCore Development Commands"
	@echo "=============================="
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

install: ## نصب dependencies اصلی
	pip install --upgrade pip
	pip install -r requirements.txt

install-dev: ## نصب dependencies توسعه
	pip install --upgrade pip
	pip install -r requirements.txt
	pip install -r requirements-dev.txt
	pre-commit install

format: ## فرمت کردن کد با Ruff
	ruff format .

lint: ## بررسی linting (بدون اصلاح)
	ruff check .

lint-fix: ## بررسی و اصلاح خودکار linting
	ruff check --fix .

check: format lint ## فرمت و lint (برای pre-commit)
	@echo "✓ All checks passed"

check-conflicts: ## بررسی merge conflicts
	python scripts/check_merge_conflicts.py

test: ## اجرای تست‌ها
	python run_tests.py

test-smoke: ## اجرای smoke tests
	python tests/smoke_test.py

ci-local: check-conflicts format lint ## اجرای تمام CI checks محلی
	@echo ""
	@echo "✓ All CI checks passed locally!"

clean: ## پاک کردن فایل‌های موقت
	find . -type d -name "__pycache__" -exec rm -r {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type d -name "*.egg-info" -exec rm -r {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -r {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -r {} + 2>/dev/null || true
	@echo "✓ Cleaned temporary files"

setup: install-dev ## راه‌اندازی کامل محیط توسعه
	@echo "✓ Development environment setup complete!"

