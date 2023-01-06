@echo off
set DIR=%~dp0

echo "**************************************************************************"
echo "** This tool will be deprecated in the next major release of OpenSearch **"
echo "** https://github.com/opensearch-project/security/issues/1755           **"
echo "**************************************************************************"

if defined OPENSEARCH_JAVA_HOME (
  set BIN_PATH="%OPENSEARCH_JAVA_HOME%\bin\java.exe"
) else if defined JAVA_HOME (
  set BIN_PATH="%JAVA_HOME%\bin\java.exe"
) else (
  echo Unable to find java runtime
  echo OPENSEARCH_JAVA_HOME or JAVA_HOME must be defined
  exit /b 1
)

%BIN_PATH% -cp "%DIR%\..\*;%DIR%\..\..\..\lib\*;%DIR%\..\deps\*" org.opensearch.security.tools.AuditConfigMigrater %*
