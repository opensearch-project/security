@echo off
set DIR=%~dp0
set CUR_DIR=%DIR%

if not defined OPENSEARCH_HOME (
  set "OPENSEARCH_HOME=%DIR%"
  :find_home
  if exist "%OPENSEARCH_HOME%lib\opensearch-*.jar" goto found_home
  for %%I in ("%OPENSEARCH_HOME%.") do set "PARENT=%%~dpI"
  if "%PARENT%" == "%OPENSEARCH_HOME%" (
    echo Could not locate OpenSearch home. Set OPENSEARCH_HOME manually. 1>&2
    exit /b 1
  )
  set "OPENSEARCH_HOME=%PARENT%"
  goto find_home
  :found_home
)
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
  echo "could not find java in %JAVA_TYPE% at %JAVA%" 1>&2
  exit /b 1
)

"%JAVA%" -Dorg.apache.logging.log4j.simplelog.StatusLogger.level=OFF -cp "%PLUGIN_DIR%\*;%PLUGIN_DIR%\deps\*;%OPENSEARCH_HOME%lib\*" org.opensearch.security.tools.democonfig.Installer "%OPENSEARCH_HOME%" %* 2> nul
