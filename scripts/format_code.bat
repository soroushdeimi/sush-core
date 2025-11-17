@echo off
echo Formatting code with ruff and black...

ruff format .
ruff check --fix .
black .

echo Code formatting complete!

