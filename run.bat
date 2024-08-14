@echo off
SETLOCAL

REM Set project directory
SET PROJECT_DIR=%~dp0
SET VENV_DIR=%PROJECT_DIR%\.venv
SET VENV_SCRIPTS=%VENV_DIR%\Scripts
SET PYTHON_EXEC=%VENV_SCRIPTS%\python.exe

REM Create virtual environment if it does not exist
IF NOT EXIST "%VENV_DIR%" (
    echo Creating virtual environment...
    python -m venv %VENV_DIR%
)

REM Activate virtual environment
echo Activating virtual environment...
call %VENV_SCRIPTS%\activate

REM Upgrade pip
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
