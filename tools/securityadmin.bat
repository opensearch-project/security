@echo off

set OPENSEARCH_MAIN_CLASS=org.opensearch.security.tools.SecurityAdmin
set OPENSEARCH_ADDITIONAL_CLASSPATH_DIRECTORIES=plugins/opensearch-security

rem Forward JAVA_OPTS into OPENSEARCH_JAVA_OPTS for backward compatibility
if defined JAVA_OPTS (
    set OPENSEARCH_JAVA_OPTS=%JAVA_OPTS% %OPENSEARCH_JAVA_OPTS%
)

"%~dp0..\..\..\bin\opensearch-cli.bat" %*
