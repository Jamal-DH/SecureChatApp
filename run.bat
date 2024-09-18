@echo off
powershell -command "Write-Host 'Created by: ' -NoNewline -ForegroundColor Yellow -BackgroundColor Black; Write-Host '<<(JAMAL_DH)>>' -ForegroundColor Blue -BackgroundColor Black"

SETLOCAL

REM Check if the script is running with administrator privileges
net session >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo Requesting administrator privileges...
    powershell -Command "Start-Process cmd -ArgumentList '/c %~dpnx0' -Verb RunAs"
    exit /b
)

REM Set project directory
SET PROJECT_DIR=%~dp0
SET VENV_DIR=%PROJECT_DIR%\.venv
SET VENV_SCRIPTS=%VENV_DIR%\Scripts
SET PYTHON_EXEC=%VENV_SCRIPTS%\python.exe

REM Check if SSH service is running
echo Checking if SSH service is running...
sc query sshd | find "RUNNING" >nul 2>&1
IF ERRORLEVEL 1 (
    echo SSH service is not running. Attempting to start the SSH service...
    net start sshd
    IF ERRORLEVEL 1 (
        echo Failed to start SSH service. Please ensure SSH is installed and try again.
        pause
        exit /b 1
    ) ELSE (
        echo SSH service started successfully.
    )
) ELSE (
    echo SSH service is already running.
)

REM Create virtual environment if it does not exist
IF NOT EXIST "%VENV_DIR%" (
    echo Creating virtual environment...
    python -m venv %VENV_DIR%
)

REM Activate virtual environment
echo Activating virtual environment...
call %VENV_SCRIPTS%\activate

REM Upgrade pip to the latest version
echo Upgrading pip...
%PYTHON_EXEC% -m pip install --upgrade pip

REM Install and upgrade all dependencies to the latest version
echo Upgrading all dependencies to the latest version...
%PYTHON_EXEC% -m pip install --upgrade -r "%PROJECT_DIR%python\requirements.txt"

REM Set environment variables
echo Setting environment variables...
SET PATH=%PROJECT_DIR%\ssl\OpenSSL-Win64\bin;%PATH%

REM Run the program
echo Running the program...
%PYTHON_EXEC% "%PROJECT_DIR%python\main.py"

pause
ENDLOCAL
