@echo off
set SCRIPT_DIR=%~dp0
"%JAVA_HOME%\bin\java" -cp "%SCRIPT_DIR%\..\..\opendistro_security_ssl\*;%SCRIPT_DIR%\..\deps\*;%SCRIPT_DIR%\..\*;%SCRIPT_DIR%\..\..\..\lib\*" com.amazon.opendistroforelasticsearch.security.tools.AuditConfigMigrater %*
