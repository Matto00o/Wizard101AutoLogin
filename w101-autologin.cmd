@echo off
rem Windows launcher: start the client without the launcher, then auto-login.
rem
rem Credentials live in %APPDATA%\w101-autologin\credentials, username on the
rem first line and password on the second.
rem
rem Edit GAME_DIR below if Wizard101 is installed elsewhere.

setlocal

set "GAME_DIR=%PROGRAMDATA%\KingsIsle Entertainment\Wizard101"
set "CREDS=%APPDATA%\w101-autologin\credentials"
set "INJECTOR=%~dp0dist\w101_autologin_c.exe"
set "LOGIN_SERVER=login.us.wizard101.com:12000"

if not exist "%INJECTOR%" (
    echo Injector not found: %INJECTOR%
    exit /b 1
)
if not exist "%CREDS%" (
    echo Credentials file not found: %CREDS%
    echo Create it with the username on line 1 and the password on line 2.
    exit /b 1
)
if not exist "%GAME_DIR%\Bin\WizardGraphicalClient.exe" (
    echo Client not found under %GAME_DIR%\Bin
    echo Edit GAME_DIR in this script.
    exit /b 1
)

"%INJECTOR%" --launch "%GAME_DIR%" --login-server "%LOGIN_SERVER%" --credentials-file "%CREDS%"
exit /b %ERRORLEVEL%
