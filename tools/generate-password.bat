@echo off
setlocal enableDelayedExpansion

REM Set the directory of the current script
set "SCRIPT_DIR=%~dp0"

REM Set the desired password length
set "length=16"

REM Define the character set for the password
set "characters=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

REM Initialize the password variable
set "password="

REM Loop to generate the random password
for /l %%i in (1,1,%length%) do (
    set /a "index=!random! %% 62"
    for %%c in (!index!) do (
        set "char=!characters:~%%c,1!"
        set "password=!password!!char!"
    )
)
