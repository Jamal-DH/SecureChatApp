@echo off
setlocal

REM Function to check for errors and pause if any
:CheckError
if %errorlevel% neq 0 (
    echo An error occurred. Exiting...
    pause
    exit /b %errorlevel%
)

echo Checking if Python is installed...
python --version
if %errorlevel% neq 0 (
    echo Python is not installed.
    echo Downloading Python...
    REM Download and install Python
    powershell -command "Invoke-WebRequest -Uri https://www.python.org/ftp/python/3.12.4/python-3.12.4-amd64.exe -OutFile python_installer.exe"
    if %errorlevel% neq 0 (
        echo Failed to download Python installer.
        pause
        exit /b %errorlevel%
    )
    echo Installing Python...
    python_installer.exe /quiet InstallAllUsers=1 PrependPath=1
    if %errorlevel% neq 0 (
        echo Failed to install Python.
        pause
        exit /b %errorlevel%
    )
    del python_installer.exe
    if %errorlevel% neq 0 (
        echo Failed to delete Python installer.
        pause
        exit /b %errorlevel%
    )
)

echo Python is installed. Checking pip...
python -m pip --version
if %errorlevel% neq 0 (
    echo Pip is not available. Ensure Python installation includes pip.
    pause
    exit /b %errorlevel%
)

REM Install required Python modules
echo Installing required Python modules...
python -m pip install --upgrade pip
if %errorlevel% neq 0 (
    echo Failed to upgrade pip.
    pause
    exit /b %errorlevel%
)
python -m pip install psutil GPUtil tabulate wmi
if %errorlevel% neq 0 (
    echo Failed to install required Python modules.
    pause
    exit /b %errorlevel%
)

REM Navigate to the directory where the Python script is located
echo Navigating to the script directory...
cd /d "C:\Users\RTX\Desktop"
if %errorlevel% neq 0 (
    echo Failed to navigate to script directory.
    pause
    exit /b %errorlevel%
)

REM Run the Python script
echo Running the Python script...
python test.py
if %errorlevel% neq 0 (
    echo Python script execution failed.
    pause
    exit /b %errorlevel%
)

echo Script completed successfully.
endlocal
pause