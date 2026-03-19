@echo off
set DIR=%~dp0

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

set "PLUGIN_DIR=%OPENSEARCH_HOME%plugins\opensearch-security"

if defined OPENSEARCH_JAVA_HOME (
  set BIN_PATH="%OPENSEARCH_JAVA_HOME%\bin\java.exe"
) else if defined JAVA_HOME (
  set BIN_PATH="%JAVA_HOME%\bin\java.exe"
) else (
  echo Unable to find java runtime
  echo OPENSEARCH_JAVA_HOME or JAVA_HOME must be defined
  exit /b 1
)

%BIN_PATH% -cp "%PLUGIN_DIR%\*;%PLUGIN_DIR%\deps\*;%OPENSEARCH_HOME%lib\*" org.opensearch.security.tools.AuditConfigMigrater %*
