@echo off
set DIR=%~dp0
set CUR_DIR=%DIR%

if defined OPENSEARCH_HOME goto find_home_done

set "OPENSEARCH_HOME=%DIR%"
:find_home
if exist "%OPENSEARCH_HOME%lib\opensearch-*.jar" goto find_home_done
for %%I in ("%OPENSEARCH_HOME%.") do set "PARENT=%%~dpI"
if "%PARENT%" == "%OPENSEARCH_HOME%" (
  echo Could not locate OpenSearch home. Set OPENSEARCH_HOME manually. 1>&2
  exit /b 1
)
set "OPENSEARCH_HOME=%PARENT%"
goto find_home
:find_home_done
cd %CUR_DIR%

set "PLUGIN_DIR=%OPENSEARCH_HOME%plugins\opensearch-security"

if not "%OPENSEARCH_JAVA_HOME%" == "" (
  set "JAVA=%OPENSEARCH_JAVA_HOME%\bin\java.exe"
  set JAVA_TYPE=OPENSEARCH_JAVA_HOME
) else if not "%JAVA_HOME%" == "" (
  set "JAVA=%JAVA_HOME%\bin\java.exe"
  set JAVA_TYPE=JAVA_HOME
) else (
  set "JAVA=%OPENSEARCH_HOME%jdk\bin\java.exe"
  set "JAVA_HOME=%OPENSEARCH_HOME%jdk"
  set JAVA_TYPE=bundled jdk
)

if not exist "%JAVA%" (
  echo could not find java in %JAVA_TYPE% at %JAVA% 1>&2
  exit /b 1
)

set "OPENSEARCH_HOME_ARG=%OPENSEARCH_HOME%"
if "%OPENSEARCH_HOME_ARG:~-1%" == "\" set "OPENSEARCH_HOME_ARG=%OPENSEARCH_HOME_ARG:~0,-1%"

"%JAVA%" -Dorg.apache.logging.log4j.simplelog.StatusLogger.level=OFF -cp "%PLUGIN_DIR%\*;%PLUGIN_DIR%\deps\*;%OPENSEARCH_HOME%lib\*" org.opensearch.security.tools.democonfig.Installer "%OPENSEARCH_HOME_ARG%" %* 2> nul
