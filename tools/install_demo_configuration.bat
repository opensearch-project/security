@echo off
set DIR=%~dp0

set CUR_DIR=%DIR%

rem set opensearch home for instances when using bundled jdk
if not defined OPENSEARCH_HOME (
  for %%I in ("%DIR%..\..\..") do set "OPENSEARCH_HOME=%%~dpfI"
)
cd %CUR_DIR%

if not "%OPENSEARCH_JAVA_HOME%" == "" (
  set "JAVA=%OPENSEARCH_JAVA_HOME%\bin\java.exe"
  set JAVA_TYPE=OPENSEARCH_JAVA_HOME
) else if not "%JAVA_HOME%" == "" (
  set "JAVA=%JAVA_HOME%\bin\java.exe"
  set JAVA_TYPE=JAVA_HOME
) else (
  set "JAVA=%OPENSEARCH_HOME%\jdk\bin\java.exe"
  set "JAVA_HOME=%OPENSEARCH_HOME%\jdk"
  set JAVA_TYPE=bundled jdk
)

if not exist "%JAVA%" (
  echo "could not find java in %JAVA_TYPE% at %JAVA%" >&2
  exit /b 1
)

"%JAVA%" -Dorg.apache.logging.log4j.simplelog.StatusLogger.level=OFF -cp "%DIR%\..\*;%DIR%\..\..\..\lib\*;%DIR%\..\deps\*" org.opensearch.security.tools.democonfig.Installer %DIR% %* 2> nul
