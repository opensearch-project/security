@echo off
set SCRIPT_DIR=%~dp0

echo "**************************************************************************"
echo "** This tool will be deprecated in the next major release of OpenSearch **"
echo "** https://github.com/opensearch-project/security/issues/1755           **"
echo "**************************************************************************"

rem comparing to empty string makes this equivalent to bash -v check on env var
if not "%OPENSEARCH_JAVA_HOME%" == "" (
  set BIN_PATH="%OPENSEARCH_JAVA_HOME%\bin\java.exe"
) else (
  set BIN_PATH="%JAVA_HOME%\bin\java.exe"
)

%BIN_PATH% -cp "%SCRIPT_DIR%\..\..\opendistro_security_ssl\*;%SCRIPT_DIR%\..\deps\*;%SCRIPT_DIR%\..\*;%SCRIPT_DIR%\..\..\..\lib\*" org.opensearch.security.tools.Hasher %*

