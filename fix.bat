@echo off
REM ========================================
REM Script to recreate the Python virtual environment
REM Used to fix project issues by resetting the environment
REM ========================================

SETLOCAL ENABLEEXTENSIONS
SET "REQUIREMENTS_FILE=%PROJECT_DIR%python\requirements.txt"

REM --- Remove Existing Virtual Environment ---
echo Removing existing virtual environment...
IF EXIST ".venv\" (
    rmdir /S /Q ".venv"
    IF %ERRORLEVEL% NEQ 0 (
        echo Failed to remove existing virtual environment.
        pause
        exit /b 1
    ) ELSE (
        echo Existing virtual environment removed successfully.
    )
) ELSE (
    echo No existing virtual environment found.
)

REM --- Check if Python is Installed ---
python --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo Python is not installed or not in PATH. Please install Python and try again.
    pause
    exit /b 1
)

REM --- Create a New Virtual Environment ---
echo Creating new virtual environment...
python -m venv ".venv"
IF %ERRORLEVEL% NEQ 0 (
    echo Failed to create virtual environment.
    pause
    exit /b 1
) ELSE (
    echo Virtual environment created successfully.
)

REM --- Activate the Virtual Environment ---
echo Activating virtual environment...
call ".venv\Scripts\activate"
IF %ERRORLEVEL% NEQ 0 (
    echo Failed to activate virtual environment.
    pause
    exit /b 1
)

REM --- Upgrade pip to the Latest Version ---
echo Upgrading pip to the latest version...
pip install --upgrade pip
pip install --upgrade web3
IF %ERRORLEVEL% NEQ 0 (
    echo Failed to upgrade pip.
    pause
    exit /b 1
) ELSE (
    echo Pip upgraded successfully.
)

IF EXIST "%REQUIREMENTS_FILE%" (
    echo Installing dependencies from %REQUIREMENTS_FILE%...
    pip install -r "%REQUIREMENTS_FILE%"
    IF %ERRORLEVEL% NEQ 0 (
        echo Failed to install dependencies.
        pause
        exit /b 1
    ) ELSE (
        echo Dependencies installed successfully.
    )
) ELSE (
    echo %REQUIREMENTS_FILE% not found.
    pause
    exit /b 1
)
ENDLOCAL
echo Virtual environment setup completed successfully.
pause
