@echo off

set OPENSEARCH_MAIN_CLASS=org.opensearch.security.tools.SecurityAdmin
set OPENSEARCH_ADDITIONAL_CLASSPATH_DIRECTORIES=plugins/opensearch-security;plugins/opensearch-security/deps

"%~dp0..\bin\opensearch-cli.bat" %*