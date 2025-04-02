@echo off
REM ========================================
REM Script to set up and run a Python project
REM Created by: <<(JAMAL_DH)>>
REM ========================================

REM Display a colored "Created by" message using PowerShell
powershell -command ^
    "Write-Host 'Created by: ' -NoNewline -ForegroundColor Yellow; " ^
    "Write-Host '<<(JAMAL_DH)>>' -ForegroundColor Blue"

SETLOCAL ENABLEEXTENSIONS

:CHECK_ADMIN
REM --- Check for Administrator Privileges ---
net session >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo Requesting administrator privileges...
    powershell -Command "Start-Process cmd -ArgumentList '/c \"%~dpnx0\"' -Verb RunAs"
    exit /b
)

REM --- Set up Directories and Variables ---
SET "PROJECT_DIR=%~dp0"
SET "VENV_DIR=%PROJECT_DIR%\.venv"
SET "VENV_SCRIPTS=%VENV_DIR%\Scripts"
SET "PYTHON_EXEC=%VENV_SCRIPTS%\python.exe"
SET "REQUIREMENTS_FILE=%PROJECT_DIR%python\requirements.txt"
SET "MAIN_SCRIPT=%PROJECT_DIR%python\main.py"
SET "OPENSSL_BIN=%PROJECT_DIR%ssl\OpenSSL-Win64\bin"

REM --- Check if Python is Installed ---
python --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo Python is not installed or not in PATH. Please install Python and try again.
    pause
    exit /b 1
)

REM ------------------------------------------------------------------------
REM SECTION: Ensure OpenSSH is Installed and Running
REM ------------------------------------------------------------------------
:CHECK_SSH
:: 1) Check if the "sshd" service even exists (i.e., OpenSSH is installed)
sc query sshd 2>&1 | find /I "does not exist" >nul
IF %ERRORLEVEL%==0 (
    echo.
    echo [ERROR] OpenSSH/sshd service does not appear to be installed.
    echo        Please install OpenSSH first, then re-run this script.
    echo.
    pause
    exit /b 1
)

:: 2) Check if sshd is already running
sc query sshd | find /I "RUNNING" >nul
IF %ERRORLEVEL% NEQ 0 (
    echo SSH service is not running. Attempting to start the SSH service...
    net start sshd
    IF %ERRORLEVEL% NEQ 0 (
        echo Failed to start SSH service. Please ensure SSH is installed and try again.
        pause
        exit /b 1
    ) ELSE (
        echo SSH service started successfully.
        echo Re-running the script to continue setup...
        echo.
        :: Re-run the same script with admin privileges
        call "%~dpnx0"
        exit /b
    )
) ELSE (
    echo SSH service is already running.
)
REM ------------------------------------------------------------------------
REM END SECTION: Ensure OpenSSH is Installed and Running
REM ------------------------------------------------------------------------

REM --- Create Virtual Environment if Not Exists ---
IF NOT EXIST "%VENV_DIR%" (
    echo Creating virtual environment...
    python -m venv "%VENV_DIR%"
    IF %ERRORLEVEL% NEQ 0 (
        echo Failed to create virtual environment.
        pause
        exit /b 1
    )
)

REM --- Upgrade pip ---
echo Upgrading pip to the latest version...
"%PYTHON_EXEC%" -m pip install --upgrade pip
IF %ERRORLEVEL% NEQ 0 (
    echo Failed to upgrade pip.
    pause
    exit /b 1
)

REM --- Install/Upgrade Dependencies ---
IF EXIST "%REQUIREMENTS_FILE%" (
    echo Installing and upgrading dependencies from requirements.txt...
    "%PYTHON_EXEC%" -m pip install --upgrade -r "%REQUIREMENTS_FILE%"
    IF %ERRORLEVEL% NEQ 0 (
        echo Failed to install dependencies.
        pause
        exit /b 1
    )
) ELSE (
    echo Requirements file not found at "%REQUIREMENTS_FILE%".
    pause
    exit /b 1
)

REM --- Set Environment Variables ---
echo Setting environment variables...
SET "PATH=%OPENSSL_BIN%;%PATH%"

REM --- Run the Program ---
IF EXIST "%MAIN_SCRIPT%" (
    echo Running the program...
    "%PYTHON_EXEC%" "%MAIN_SCRIPT%"
    IF %ERRORLEVEL% NEQ 0 (
        echo Program exited with errors.
        pause
        exit /b 1
    )
) ELSE (
    echo Main script not found at "%MAIN_SCRIPT%".
    pause
    exit /b 1
)

pause
ENDLOCAL
