@echo off
::
:: Copyright OpenSearch Contributors
:: SPDX-License-Identifier: Apache-2.0
::
:: Generates BCFKS counterparts for every JKS / PKCS12 keystore under
:: src\test\resources\.  See README.md for usage and prerequisites.

setlocal enabledelayedexpansion

if "%BC_FIPS_JAR%"=="" (
    echo ERROR: BC_FIPS_JAR is not set. Point it to the bc-fips-*.jar, e.g.: >&2
    echo   set BC_FIPS_JAR=C:\path\to\bc-fips-2.1.2.jar >&2
    exit /b 1
)

set SCRIPT_DIR=%~dp0
set RESOURCES=%SCRIPT_DIR%..
:: Resolve to absolute path
pushd "%RESOURCES%"
set RESOURCES=%CD%
popd

set BC_FIPS=%BC_FIPS_JAR%

set CONVERTED=0

:: ── JKS-only keystores ────────────────────────────────────────────────────────

echo === Converting JKS-only keystores ===

for %%F in (
    cache\kirk-keystore.jks
    cache\node-0-keystore.jks
    cache\spock-keystore.jks
    cache\truststore.jks
    dlsfls\kirk-keystore.jks
    dlsfls\node-0-keystore.jks
    dlsfls\spock-keystore.jks
    dlsfls\truststore.jks
    jwt\kirk-keystore.jks
    jwt\node-0-keystore.jks
    jwt\spock-keystore.jks
    jwt\truststore.jks
    ldap\kirk-keystore.jks
    ldap\node-0-keystore.jks
    ldap\spock-keystore.jks
    ldap\truststore.jks
    migration\kirk-keystore.jks
    migration\node-0-keystore.jks
    migration\spock-keystore.jks
    migration\truststore.jks
    multitenancy\kirk-keystore.jks
    multitenancy\node-0-keystore.jks
    multitenancy\spock-keystore.jks
    multitenancy\truststore.jks
    restapi\kirk-keystore.jks
    restapi\node-0-keystore.jks
    restapi\spock-keystore.jks
    restapi\truststore.jks
    sanity-tests\kirk-keystore.jks
    ssl\extended_key_usage\node-0-keystore.jks
    ssl\extended_key_usage\truststore.jks
    ssl\reload\kirk-keystore.jks
    ssl\reload\spock-keystore.jks
    ssl\reload\truststore.jks
    ssl\truststore.jks
    ssl\truststore_fail.jks
    ssl\truststore_invalid.jks
    ssl\truststore_valid.jks
    auditlog\truststore.jks
    auditlog\truststore_fail.jks
    kirk-keystore.jks
    node-0-keystore.jks
    node-1-keystore.jks
    node-2-keystore.jks
    spock-keystore.jks
    truststore.jks
    truststore_fail.jks
) do (
    set SRC=%RESOURCES%\%%F
    set DEST=!SRC:.jks=.bcfks!
    java --enable-native-access=ALL-UNNAMED -cp "%BC_FIPS%" "%SCRIPT_DIR%ConvertKeystore.java" "!SRC!" JKS changeit "!DEST!" changeit
    set /a CONVERTED+=1
)

:: ── PKCS12 keystores ──────────────────────────────────────────────────────────

echo.
echo === Converting PKCS12 keystores (preferred source for shared base names) ===

for %%F in (
    auditlog\kirk-keystore.p12
    auditlog\node-0-keystore.p12
    auditlog\spock-keystore.p12
    ssl\kirk-keystore.p12
    ssl\node-0-keystore.p12
    ssl\node-1-keystore.p12
    ssl\node-2-keystore.p12
    ssl\spock-keystore.p12
    ssl\node-untspec5-keystore.p12
    node-untspec5-keystore.p12
    node-untspec6-keystore.p12
) do (
    set SRC=%RESOURCES%\%%F
    set DEST=!SRC:.p12=.bcfks!
    java --enable-native-access=ALL-UNNAMED -cp "%BC_FIPS%" "%SCRIPT_DIR%ConvertKeystore.java" "!SRC!" PKCS12 changeit "!DEST!" changeit
    set /a CONVERTED+=1
)

:: ── sslConfigurator keystores (password: secret) ──────────────────────────────

echo.
echo === Converting sslConfigurator keystores (password: secret) ===

for %%F in (
    sslConfigurator\jks\node1-keystore.jks
    sslConfigurator\jks\other-root-ca.jks
    sslConfigurator\jks\truststore.jks
    sslConfigurator\pem\node-wrong-hostname-keystore.jks
    sslConfigurator\pem\node1-keystore.jks
    sslConfigurator\pem\truststore.jks
) do (
    set SRC=%RESOURCES%\%%F
    set DEST=!SRC:.jks=.bcfks!
    java --enable-native-access=ALL-UNNAMED -cp "%BC_FIPS%" "%SCRIPT_DIR%ConvertKeystore.java" "!SRC!" JKS secret "!DEST!" secret
    set /a CONVERTED+=1
)

echo.
echo Done. %CONVERTED% BCFKS files written alongside their source keystores.

endlocal
