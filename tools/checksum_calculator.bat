@echo off
setlocal enabledelayedexpansion

set "DIR=%~dp0"

if defined OPENSEARCH_JAVA_HOME (
  set BIN_PATH=%OPENSEARCH_JAVA_HOME%\bin\java.exe
) else if defined JAVA_HOME (
  set BIN_PATH=%JAVA_HOME%\bin\java.exe
) else (
  echo Unable to find Java runtime.
  echo OPENSEARCH_JAVA_HOME or JAVA_HOME must be defined.
  exit /b 1
)

"%BIN_PATH%" -cp "%DIR%\..\*;%DIR%\..\..\..\lib\*;%DIR%\..\deps\*" org.opensearch.security.tools.ChecksumCalculator %*
