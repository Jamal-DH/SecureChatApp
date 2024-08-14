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

REM Install requirements
echo Installing requirements...
%PYTHON_EXEC% -m pip install --upgrade pip
%PYTHON_EXEC% -m pip install -r "%PROJECT_DIR%python\requirements.txt"

REM Set environment variables
echo Setting environment variables...
SET PATH=%PROJECT_DIR%\ssl\OpenSSL-Win64\bin;%PATH%

REM Print skeleton with red color using PowerShell
powershell -command "Write-Host '                     ______' -ForegroundColor Red"
powershell -command "Write-Host '                  .-\"      \"-.' -ForegroundColor Red"
powershell -command "Write-Host '                 /            \' -ForegroundColor Red"
powershell -command "Write-Host '                |              |' -ForegroundColor Red"
powershell -command "Write-Host '                |,  .-.  .-.  ,|' -ForegroundColor Red"
powershell -command "Write-Host '                | )(_o/  \o_)( |' -ForegroundColor Red"
powershell -command "Write-Host '                |/     /\     \|' -ForegroundColor Red"
powershell -command "Write-Host '      (@_       (_     ^^     _)' -ForegroundColor Red"
powershell -command "Write-Host ' _     ) \_______\__|IIIIII|__/_____________________________' -ForegroundColor Red"
powershell -command "Write-Host '(_)XXX{} <________|-\IIIIII/-|_______________________________>' -ForegroundColor Red"
powershell -command "Write-Host '       )_/        \          /' -ForegroundColor Red"
powershell -command "Write-Host '      (@           `--------`' -ForegroundColor Red"

powershell -command "Write-Host '                     Jimmie   '-ForegroundColor Red"

REM Run the program
echo Running the program...
%PYTHON_EXEC% "%PROJECT_DIR%python\main.py"

pause
ENDLOCAL
