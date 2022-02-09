@echo off
set SCRIPT_DIR=%~dp0

rem comparing to empty string makes this equivalent to bash -v check on env var
if not "%OPENSEARCH_JAVA_HOME%" == "" (
  set BIN_PATH="%OPENSEARCH_JAVA_HOME%\bin\java.exe"
) else (
  set BIN_PATH="%JAVA_HOME%\bin\java.exe"
)

%BIN_PATH% -Dorg.apache.logging.log4j.simplelog.StatusLogger.level=OFF -cp "%SCRIPT_DIR%\..\..\opendistro_security-ssl\*;%SCRIPT_DIR%\..\deps\*;%SCRIPT_DIR%\..\*;%SCRIPT_DIR%\..\..\..\lib\*" org.opensearch.security.tools.SecurityAdmin %* 2> nul
