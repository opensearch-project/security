@echo off
set SCRIPT_DIR=%~dp0
"%JAVA_HOME%\bin\java" -Dorg.apache.logging.log4j.simplelog.StatusLogger.level=OFF -cp "%SCRIPT_DIR%\..\..\opendistro_security-ssl\*;%SCRIPT_DIR%\..\deps\*;%SCRIPT_DIR%\..\*;%SCRIPT_DIR%\..\..\..\lib\*" org.opensearch.security.tools.SecurityAdmin %* 2> nul
