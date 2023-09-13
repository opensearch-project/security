@echo off
setlocal enableDelayedExpansion
set "SCRIPT_DIR=%~dp0"

set "CUR=%cd%"
cd %BASE_DIR%
set "BASE_DIR=%cd%\"
cd %CUR%
echo Basedir: %BASE_DIR%

set "OPENSEARCH_CONF_FILE=%BASE_DIR%config\opensearch.yml"
set "INTERNAL_USERS_FILE"=%BASE_DIR%config\internal_users.yml"

for /f "tokens=2 delims=: " %%a in ('findstr /r "plugins.security.bootstrap.admin.password:" "%OPENSEARCH_CONF_FILE%"') do (
    set "ADMIN_PASSWORD=%%a"
)

REM If ADMIN_PASSWORD is empty, check the environment variable as a fallback
if not defined ADMIN_PASSWORD (
    if defined ENV_ADMIN_PASSWORD (
        set "ADMIN_PASSWORD=!ENV_ADMIN_PASSWORD!"
    ) else (
        echo Admin password not found in %OPENSEARCH_CONF_FILE% and ENV_ADMIN_PASSWORD is not set.
        exit /b 1
    )
)

set "salt="
for /l %%i in (1,1,16) do (
    set /a "rand=!random! %% 16"
    set "salt=!salt!!rand!"
)

openssl passwd -bcrypt -salt !salt! "!ADMIN_PASSWORD!" > tmp_hash.txt

set "HASHED_ADMIN_PASSWORD="
for /f %%a in (tmp_hash.txt) do (
    set "HASHED_ADMIN_PASSWORD=%%a"
)

del tmp_hash.txt

for /f "tokens=1 delims=:" %%b in ('findstr /n "admin:" "%INTERNAL_USERS_FILE%"') do (
    set "ADMIN_HASH_LINE=%%b"
)

(for /f "delims=" %%c in ('type "%INTERNAL_USERS_FILE%" ^| findstr /n "^"') do (
    set "line=%%c"
    setlocal enabledelayedexpansion
    echo(!line:%ADMIN_HASH_LINE%:=! | findstr "^"
    endlocal
)) > tmp_internal_users.yml

(for /f "delims=" %%d in ('type "tmp_internal_users.yml" ^| findstr /n "^"') do (
    set "line=%%d"
    setlocal enabledelayedexpansion
    if !line:^%ADMIN_HASH_LINE%^=! neq !line! (
        echo !line!
    ) else (
        echo !line!
        echo hash: "!HASHED_ADMIN_PASSWORD!"
    )
    endlocal
)) > "%INTERNAL_USERS_FILE%"

del tmp_internal_users.yml
