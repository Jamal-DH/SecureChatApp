@echo off
SETLOCAL

REM Remove existing virtual environment
rmdir /S /Q .venv

REM Create a new virtual environment
python -m venv .venv

REM Activate the virtual environment
call .venv\Scripts\activate

REM Upgrade pip to the latest version
pip install --upgrade pip

REM Install dependencies from requirements.txt
pip install -r requirements.txt

ENDLOCAL
