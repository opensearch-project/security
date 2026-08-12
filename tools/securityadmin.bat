@echo off

setlocal enabledelayedexpansion
setlocal enableextensions

set "CALLER_DIR=%CD%"
set DIR=%~dp0

if not defined OPENSEARCH_HOME goto find_home_start
if not "%OPENSEARCH_HOME:~-1%"=="\" set "OPENSEARCH_HOME=%OPENSEARCH_HOME%\"
goto find_home_done

:find_home_start
set "OPENSEARCH_HOME=%DIR%"
:find_home
if exist "%OPENSEARCH_HOME%lib\opensearch-*.jar" goto find_home_found
for %%I in ("%OPENSEARCH_HOME%.") do set "PARENT=%%~dpI"
if "%PARENT%" == "%OPENSEARCH_HOME%" (
  echo Could not locate OpenSearch home. Set OPENSEARCH_HOME manually. 1>&2
  exit /b 1
)
set "OPENSEARCH_HOME=%PARENT%"
goto find_home
:find_home_found
rem Drop the trailing backslash left by %%~dp: a trailing backslash would escape the
rem closing quote in -Dopensearch.path.home="...\".
set "OPENSEARCH_HOME=%OPENSEARCH_HOME:~0,-1%"
:find_home_done

rem Forward JAVA_OPTS into OPENSEARCH_JAVA_OPTS for backward compatibility
if defined JAVA_OPTS (
    set OPENSEARCH_JAVA_OPTS=%JAVA_OPTS% %OPENSEARCH_JAVA_OPTS%
)
set JAVA_OPTS=

rem Core launcher environment: java lookup and version check, OPENSEARCH_PATH_CONF and,
rem with OPENSEARCH_FIPS_MODE=true, the FIPS JVM options. It changes into OPENSEARCH_HOME;
rem return to the caller's directory so relative -cd/-f/-backup paths resolve as documented.
call "%OPENSEARCH_HOME%\bin\opensearch-env.bat" || exit /b 1
cd /d "%CALLER_DIR%"

"%JAVA%" ^
  -Xms4m -Xmx64m -XX:+UseSerialGC ^
  %OPENSEARCH_JAVA_OPTS% ^
  -Dopensearch.path.home="%OPENSEARCH_HOME%" ^
  -Dopensearch.path.conf="%OPENSEARCH_PATH_CONF%" ^
  -Dopensearch.distribution.type="%OPENSEARCH_DISTRIBUTION_TYPE%" ^
  -cp "%OPENSEARCH_CLASSPATH%;%OPENSEARCH_HOME%\plugins\opensearch-security\*" ^
  org.opensearch.security.tools.SecurityAdmin ^
  %*

endlocal
endlocal
exit /b %ERRORLEVEL%
