@echo off
set SCRIPT_DIR=%~dp0
"%JAVA_HOME%\bin\java" -Dorg.apache.logging.log4j.simplelog.StatusLogger.level=OFF -cp "%SCRIPT_DIR%\..\..\search-guard-ssl\*;%SCRIPT_DIR%\..\deps\*;%SCRIPT_DIR%\..\*;%SCRIPT_DIR%\..\..\..\lib\*" com.floragunn.searchguard.tools.SearchGuardAdmin %* 2> nul
