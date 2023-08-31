@echo off
setlocal enableDelayedExpansion
set "SCRIPT_DIR=%~dp0"

echo **************************************************************************
echo ** This tool will be deprecated in the next major release of OpenSearch **
echo ** https://github.com/opensearch-project/security/issues/1755           **
echo **************************************************************************

echo.
echo OpenSearch Security Demo Installer
echo  ** Warning: Do not use on production or public reachable systems **

echo.

set "assumeyes=0"
set "initsecurity=0"
set "cluster_mode=0"
set "skip_updates=-1"

goto :GETOPTS

:show_help
echo install_demo_configuration.bat [-y] [-i] [-c]
echo   -h show help
echo   -y confirm all installation dialogues automatically
echo   -i initialize Security plugin with default configuration (default is to ask if -y is not given)
echo   -c enable cluster mode by binding to all network interfaces (default is to ask if -y is not given)
echo   -s skip updates if config is already applied to opensearch.yml
EXIT /B 0

:GETOPTS
if /I "%1" == "-h" call :show_help & exit /b 0
if /I "%1" == "-y" set "assumeyes=1"
if /I "%1" == "-i" set "initsecurity=1"
if /I "%1" == "-c" set "cluster_mode=1"
if /I "%1" == "-s" set "skip_updates=0"
shift
if not "%1" == "" goto :GETOPTS

if "%1" == "--" shift

if %assumeyes% == 0 (
    set /p "response=Install demo certificates? [y/N] "
    if /I "!response!" neq "Y" exit /b 0
)

if %initsecurity% == 0 (
    if %assumeyes% == 0 (
        set /p "response=Initialize Security Modules? [y/N] "
        if /I "!response!" == "Y" (set "initsecurity=1") ELSE (set "initsecurity=0")
    )
)

if %cluster_mode% == 0 (
    if %assumeyes% == 0 (
        echo Cluster mode requires maybe additional setup of:
        echo   - Virtual memory [vm.max_map_count]
        echo.
        set /p "response=Enable cluster mode? [y/N] "
        if /I "!response!" == "Y" (set "cluster_mode=1") ELSE (set "cluster_mode=0")
    )
)

set BASE_DIR=%SCRIPT_DIR%\..\..\..\
if not exist %BASE_DIR% (
    echo "basedir does not exist"
    exit /b 1
)

set "CUR=%cd%"
cd %BASE_DIR%
set "BASE_DIR=%cd%\"
cd %CUR%
echo Basedir: %BASE_DIR%

set "OPENSEARCH_CONF_FILE=%BASE_DIR%config\opensearch.yml"
set "OPENSEARCH_CONF_DIR=%BASE_DIR%config\"
set "OPENSEARCH_BIN_DIR=%BASE_DIR%bin\"
set "OPENSEARCH_PLUGINS_DIR=%BASE_DIR%plugins\"
set "OPENSEARCH_MODULES_DIR=%BASE_DIR%modules\"
set "OPENSEARCH_LIB_PATH=%BASE_DIR%lib\"
set "OPENSEARCH_INSTALL_TYPE=.zip"

if not exist %OPENSEARCH_CONF_FILE% (
    echo Unable to determine OpenSearch config file. Quit.
    exit /b 1
)

if not exist %OPENSEARCH_BIN_DIR% (
	echo Unable to determine OpenSearch bin directory. Quit.
	exit /b 1
)

if not exist %OPENSEARCH_PLUGINS_DIR% (
	echo Unable to determine OpenSearch plugins directory. Quit.
	exit /b 1
)

if not exist %OPENSEARCH_MODULES_DIR% (
	echo Unable to determine OpenSearch modules directory. Quit.
	exit /b 1
)

if not exist %OPENSEARCH_LIB_PATH% (
	echo Unable to determine OpenSearch lib directory. Quit.
	exit /b 1
)

if not exist %OPENSEARCH_PLUGINS_DIR%\opensearch-security\ (
    echo OpenSearch Security plugin not installed. Quit.
    exit /b 1
)

set "OPENSEARCH_VERSION="
for %%F in ("%OPENSEARCH_LIB_PATH%opensearch-*.jar") do set "OPENSEARCH_VERSION=%%~nxF" & goto :opensearch_version
:opensearch_version
set "OPENSEARCH_JAR_VERSION="
for /f "tokens=2 delims=[-]" %%a in ("%OPENSEARCH_VERSION%") do set "OPENSEARCH_JAR_VERSION=%%a"

set "SECURITY_VERSION="
for %%F in ("%OPENSEARCH_PLUGINS_DIR%\opensearch-security\opensearch-security-*.jar") do set "SECURITY_VERSION=%%~nxF"
set "SECURITY_JAR_VERSION="
for /f "tokens=3 delims=[-]" %%a in ("%SECURITY_VERSION%") do set "SECURITY_JAR_VERSION=%%a"

for /f "tokens=4-7 delims=[.] " %%i in ('ver') do (if %%i==Version (set "OS=%%j.%%k") else (set v="%%i.%%j"))
echo OpenSearch install type: %OPENSEARCH_INSTALL_TYPE% on %OS%
echo OpenSearch config dir: %OPENSEARCH_CONF_DIR%
echo OpenSearch config file: %OPENSEARCH_CONF_FILE%
echo OpenSearch bin dir: %OPENSEARCH_BIN_DIR%
echo OpenSearch plugins dir: %OPENSEARCH_PLUGINS_DIR%
echo OpenSearch lib dir: %OPENSEARCH_LIB_PATH%
echo Detected OpenSearch Version: %OPENSEARCH_JAR_VERSION%
echo Detected OpenSearch Security Version: %SECURITY_JAR_VERSION%

>nul findstr /c:"plugins.security" "%OPENSEARCH_CONF_FILE%" && (
  echo %OPENSEARCH_CONF_FILE% seems to be already configured for Security. Quit.
  exit /b %skip_updates%
)

set LF=^


:: two empty line required after LF
set ADMIN_CERT=-----BEGIN CERTIFICATE-----!LF!^
MIIEmDCCA4CgAwIBAgIUZjrlDPP8azRDPZchA/XEsx0X2iYwDQYJKoZIhvcNAQEL!LF!^
BQAwgY8xEzARBgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJkiaJk/IsZAEZFgdleGFt!LF!^
cGxlMRkwFwYDVQQKDBBFeGFtcGxlIENvbSBJbmMuMSEwHwYDVQQLDBhFeGFtcGxl!LF!^
IENvbSBJbmMuIFJvb3QgQ0ExITAfBgNVBAMMGEV4YW1wbGUgQ29tIEluYy4gUm9v!LF!^
dCBDQTAeFw0yMzA4MjkyMDA2MzdaFw0zMzA4MjYyMDA2MzdaME0xCzAJBgNVBAYT!LF!^
AmRlMQ0wCwYDVQQHDAR0ZXN0MQ8wDQYDVQQKDAZjbGllbnQxDzANBgNVBAsMBmNs!LF!^
aWVudDENMAsGA1UEAwwEa2lyazCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC!LF!^
ggEBAJVcOAQlCiuB9emCljROAXnlsPbG7PE3kNz2sN+BbGuw686Wgyl3uToVHvVs!LF!^
paMmLUqm1KYz9wMSWTIBZgpJ9hYaIbGxD4RBb7qTAJ8Q4ddCV2f7T4lxao/6ixI+!LF!^
O0l/BG9E3mRGo/r0w+jtTQ3aR2p6eoxaOYbVyEMYtFI4QZTkcgGIPGxm05y8xonx!LF!^
vV5pbSW9L7qAVDzQC8EYGQMMI4ccu0NcHKWtmTYJA/wDPE2JwhngHwbcIbc4cDz6!LF!^
cG0S3FmgiKGuuSqUy35v/k3y7zMHQSdx7DSR2tzhH/bBL/9qGvpT71KKrxPtaxS0!LF!^
bAqPcEkKWDo7IMlGGW7LaAWfGg8CAwEAAaOCASswggEnMAwGA1UdEwEB/wQCMAAw!LF!^
DgYDVR0PAQH/BAQDAgXgMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMCMIHPBgNVHSME!LF!^
gccwgcSAFBeH36Ba62YSp9XQ+LoSRTy3KwCcoYGVpIGSMIGPMRMwEQYKCZImiZPy!LF!^
LGQBGRYDY29tMRcwFQYKCZImiZPyLGQBGRYHZXhhbXBsZTEZMBcGA1UECgwQRXhh!LF!^
bXBsZSBDb20gSW5jLjEhMB8GA1UECwwYRXhhbXBsZSBDb20gSW5jLiBSb290IENB!LF!^
MSEwHwYDVQQDDBhFeGFtcGxlIENvbSBJbmMuIFJvb3QgQ0GCFHfkrz782p+T9k0G!LF!^
xGeM4+BrehWKMB0GA1UdDgQWBBSjMS8tgguX/V7KSGLoGg7K6XMzIDANBgkqhkiG!LF!^
9w0BAQsFAAOCAQEANMwD1JYlwAh82yG1gU3WSdh/tb6gqaSzZK7R6I0L7slaXN9m!LF!^
y2ErUljpTyaHrdiBFmPhU/2Kj2r+fIUXtXdDXzizx/JdmueT0nG9hOixLqzfoC9p!LF!^
fAhZxM62RgtyZoaczQN82k1/geMSwRpEndFe3OH7arkS/HSbIFxQhAIy229eWe5d!LF!^
1bUzP59iu7f3r567I4ob8Vy7PP+Ov35p7Vv4oDHHwgsdRzX6pvL6mmwVrQ3BfVec!LF!^
h9Dqprr+ukYmjho76g6k5cQuRaB6MxqldzUg+2E7IHQP8MCF+co51uZq2nl33mtp!LF!^
RGr6JbdHXc96zsLTL3saJQ8AWEfu1gbTVrwyRA==!LF!^
-----END CERTIFICATE-----!LF!


set ADMIN_CERT_KEY=-----BEGIN PRIVATE KEY-----!LF!^
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCVXDgEJQorgfXp!LF!^
gpY0TgF55bD2xuzxN5Dc9rDfgWxrsOvOloMpd7k6FR71bKWjJi1KptSmM/cDElky!LF!^
AWYKSfYWGiGxsQ+EQW+6kwCfEOHXQldn+0+JcWqP+osSPjtJfwRvRN5kRqP69MPo!LF!^
7U0N2kdqenqMWjmG1chDGLRSOEGU5HIBiDxsZtOcvMaJ8b1eaW0lvS+6gFQ80AvB!LF!^
GBkDDCOHHLtDXBylrZk2CQP8AzxNicIZ4B8G3CG3OHA8+nBtEtxZoIihrrkqlMt+!LF!^
b/5N8u8zB0Encew0kdrc4R/2wS//ahr6U+9Siq8T7WsUtGwKj3BJClg6OyDJRhlu!LF!^
y2gFnxoPAgMBAAECggEAP5TOycDkx+megAWVoHV2fmgvgZXkBrlzQwUG/VZQi7V4!LF!^
ZGzBMBVltdqI38wc5MtbK3TCgHANnnKgor9iq02Z4wXDwytPIiti/ycV9CDRKvv0!LF!^
TnD2hllQFjN/IUh5n4thHWbRTxmdM7cfcNgX3aZGkYbLBVVhOMtn4VwyYu/Mxy8j!LF!^
xClZT2xKOHkxqwmWPmdDTbAeZIbSv7RkIGfrKuQyUGUaWhrPslvYzFkYZ0umaDgQ!LF!^
OAthZew5Bz3OfUGOMPLH61SVPuJZh9zN1hTWOvT65WFWfsPd2yStI+WD/5PU1Doo!LF!^
1RyeHJO7s3ug8JPbtNJmaJwHe9nXBb/HXFdqb976yQKBgQDNYhpu+MYSYupaYqjs!LF!^
9YFmHQNKpNZqgZ4ceRFZ6cMJoqpI5dpEMqToFH7tpor72Lturct2U9nc2WR0HeEs!LF!^
/6tiptyMPTFEiMFb1opQlXF2ae7LeJllntDGN0Q6vxKnQV+7VMcXA0Y8F7tvGDy3!LF!^
qJu5lfvB1mNM2I6y/eMxjBuQhwKBgQC6K41DXMFro0UnoO879pOQYMydCErJRmjG!LF!^
/tZSy3Wj4KA/QJsDSViwGfvdPuHZRaG9WtxdL6kn0w1exM9Rb0bBKl36lvi7o7xv!LF!^
M+Lw9eyXMkww8/F5d7YYH77gIhGo+RITkKI3+5BxeBaUnrGvmHrpmpgRXWmINqr0!LF!^
0jsnN3u0OQKBgCf45vIgItSjQb8zonLz2SpZjTFy4XQ7I92gxnq8X0Q5z3B+o7tQ!LF!^
K/4rNwTju/sGFHyXAJlX+nfcK4vZ4OBUJjP+C8CTjEotX4yTNbo3S6zjMyGQqDI5!LF!^
9aIOUY4pb+TzeUFJX7If5gR+DfGyQubvvtcg1K3GHu9u2l8FwLj87sRzAoGAflQF!LF!^
RHuRiG+/AngTPnZAhc0Zq0kwLkpH2Rid6IrFZhGLy8AUL/O6aa0IGoaMDLpSWUJp!LF!^
nBY2S57MSM11/MVslrEgGmYNnI4r1K25xlaqV6K6ztEJv6n69327MS4NG8L/gCU5!LF!^
3pEm38hkUi8pVYU7in7rx4TCkrq94OkzWJYurAkCgYATQCL/rJLQAlJIGulp8s6h!LF!^
mQGwy8vIqMjAdHGLrCS35sVYBXG13knS52LJHvbVee39AbD5/LlWvjJGlQMzCLrw!LF!^
F7oILW5kXxhb8S73GWcuMbuQMFVHFONbZAZgn+C9FW4l7XyRdkrbR1MRZ2km8YMs!LF!^
/AHmo368d4PSNRMMzLHw8Q==!LF!^
-----END PRIVATE KEY-----!LF!


set NODE_CERT=-----BEGIN CERTIFICATE-----!LF!^
MIIEPDCCAySgAwIBAgIUZjrlDPP8azRDPZchA/XEsx0X2iIwDQYJKoZIhvcNAQEL!LF!^
BQAwgY8xEzARBgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJkiaJk/IsZAEZFgdleGFt!LF!^
cGxlMRkwFwYDVQQKDBBFeGFtcGxlIENvbSBJbmMuMSEwHwYDVQQLDBhFeGFtcGxl!LF!^
IENvbSBJbmMuIFJvb3QgQ0ExITAfBgNVBAMMGEV4YW1wbGUgQ29tIEluYy4gUm9v!LF!^
dCBDQTAeFw0yMzA4MjkwNDIzMTJaFw0zMzA4MjYwNDIzMTJaMFcxCzAJBgNVBAYT!LF!^
AmRlMQ0wCwYDVQQHDAR0ZXN0MQ0wCwYDVQQKDARub2RlMQ0wCwYDVQQLDARub2Rl!LF!^
MRswGQYDVQQDDBJub2RlLTAuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUA!LF!^
A4IBDwAwggEKAoIBAQCm93kXteDQHMAvbUPNPW5pyRHKDD42XGWSgq0k1D29C/Ud!LF!^
yL21HLzTJa49ZU2ldIkSKs9JqbkHdyK0o8MO6L8dotLoYbxDWbJFW8bp1w6tDTU0!LF!^
HGkn47XVu3EwbfrTENg3jFu+Oem6a/501SzITzJWtS0cn2dIFOBimTVpT/4Zv5qr!LF!^
XA6Cp4biOmoTYWhi/qQl8d0IaADiqoZ1MvZbZ6x76qTrRAbg+UWkpTEXoH1xTc8n!LF!^
dibR7+HP6OTqCKvo1NhE8uP4pY+fWd6b6l+KLo3IKpfTbAIJXIO+M67FLtWKtttD!LF!^
ao94B069skzKk6FPgW/OZh6PRCD0oxOavV+ld2SjAgMBAAGjgcYwgcMwRwYDVR0R!LF!^
BEAwPogFKgMEBQWCEm5vZGUtMC5leGFtcGxlLmNvbYIJbG9jYWxob3N0hxAAAAAA!LF!^
AAAAAAAAAAAAAAABhwR/AAABMAsGA1UdDwQEAwIF4DAdBgNVHSUEFjAUBggrBgEF!LF!^
BQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU0/qDQaY10jIo!LF!^
wCjLUpz/HfQXyt8wHwYDVR0jBBgwFoAUF4ffoFrrZhKn1dD4uhJFPLcrAJwwDQYJ!LF!^
KoZIhvcNAQELBQADggEBAD2hkndVih6TWxoe/oOW0i2Bq7ScNO/n7/yHWL04HJmR!LF!^
MaHv/Xjc8zLFLgHuHaRvC02ikWIJyQf5xJt0Oqu2GVbqXH9PBGKuEP2kCsRRyU27!LF!^
zTclAzfQhqmKBTYQ/3lJ3GhRQvXIdYTe+t4aq78TCawp1nSN+vdH/1geG6QjMn5N!LF!^
1FU8tovDd4x8Ib/0dv8RJx+n9gytI8n/giIaDCEbfLLpe4EkV5e5UNpOnRgJjjuy!LF!^
vtZutc81TQnzBtkS9XuulovDE0qI+jQrKkKu8xgGLhgH0zxnPkKtUg2I3Aq6zl1L!LF!^
zYkEOUF8Y25J6WeY88Yfnc0iigI+Pnz5NK8R9GL7TYo=!LF!^
-----END CERTIFICATE-----!LF!


set NODE_KEY=-----BEGIN PRIVATE KEY-----!LF!^
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCm93kXteDQHMAv!LF!^
bUPNPW5pyRHKDD42XGWSgq0k1D29C/UdyL21HLzTJa49ZU2ldIkSKs9JqbkHdyK0!LF!^
o8MO6L8dotLoYbxDWbJFW8bp1w6tDTU0HGkn47XVu3EwbfrTENg3jFu+Oem6a/50!LF!^
1SzITzJWtS0cn2dIFOBimTVpT/4Zv5qrXA6Cp4biOmoTYWhi/qQl8d0IaADiqoZ1!LF!^
MvZbZ6x76qTrRAbg+UWkpTEXoH1xTc8ndibR7+HP6OTqCKvo1NhE8uP4pY+fWd6b!LF!^
6l+KLo3IKpfTbAIJXIO+M67FLtWKtttDao94B069skzKk6FPgW/OZh6PRCD0oxOa!LF!^
vV+ld2SjAgMBAAECggEAQK1+uAOZeaSZggW2jQut+MaN4JHLi61RH2cFgU3COLgo!LF!^
FIiNjFn8f2KKU3gpkt1It8PjlmprpYut4wHI7r6UQfuv7ZrmncRiPWHm9PB82+ZQ!LF!^
5MXYqj4YUxoQJ62Cyz4sM6BobZDrjG6HHGTzuwiKvHHkbsEE9jQ4E5m7yfbVvM0O!LF!^
zvwrSOM1tkZihKSTpR0j2+taji914tjBssbn12TMZQL5ItGnhR3luY8mEwT9MNkZ!LF!^
xg0VcREoAH+pu9FE0vPUgLVzhJ3be7qZTTSRqv08bmW+y1plu80GbppePcgYhEow!LF!^
dlW4l6XPJaHVSn1lSFHE6QAx6sqiAnBz0NoTPIaLyQKBgQDZqDOlhCRciMRicSXn!LF!^
7yid9rhEmdMkySJHTVFOidFWwlBcp0fGxxn8UNSBcXdSy7GLlUtH41W9PWl8tp9U!LF!^
hQiiXORxOJ7ZcB80uNKXF01hpPj2DpFPWyHFxpDkWiTAYpZl68rOlYujxZUjJIej!LF!^
VvcykBC2BlEOG9uZv2kxcqLyJwKBgQDEYULTxaTuLIa17wU3nAhaainKB3vHxw9B!LF!^
Ksy5p3ND43UNEKkQm7K/WENx0q47TA1mKD9i+BhaLod98mu0YZ+BCUNgWKcBHK8c!LF!^
uXpauvM/pLhFLXZ2jvEJVpFY3J79FSRK8bwE9RgKfVKMMgEk4zOyZowS8WScOqiy!LF!^
hnQn1vKTJQKBgElhYuAnl9a2qXcC7KOwRsJS3rcKIVxijzL4xzOyVShp5IwIPbOv!LF!^
hnxBiBOH/JGmaNpFYBcBdvORE9JfA4KMQ2fx53agfzWRjoPI1/7mdUk5RFI4gRb/!LF!^
A3jZRBoopgFSe6ArCbnyQxzYzToG48/Wzwp19ZxYrtUR4UyJct6f5n27AoGBAJDh!LF!^
KIpQQDOvCdtjcbfrF4aM2DPCfaGPzENJriwxy6oEPzDaX8Bu/dqI5Ykt43i/zQrX!LF!^
GpyLaHvv4+oZVTiI5UIvcVO9U8hQPyiz9f7F+fu0LHZs6f7hyhYXlbe3XFxeop3f!LF!^
5dTKdWgXuTTRF2L9dABkA2deS9mutRKwezWBMQk5AoGBALPtX0FrT1zIosibmlud!LF!^
tu49A/0KZu4PBjrFMYTSEWGNJez3Fb2VsJwylVl6HivwbP61FhlYfyksCzQQFU71!LF!^
+x7Nmybp7PmpEBECr3deoZKQ/acNHn0iwb0It+YqV5+TquQebqgwK6WCLsMuiYKT!LF!^
bg/ch9Rhxbq22yrVgWHh6epp!LF!^
-----END PRIVATE KEY-----!LF!


set ROOT_CA=-----BEGIN CERTIFICATE-----!LF!^
MIIExjCCA66gAwIBAgIUd+SvPvzan5P2TQbEZ4zj4Gt6FYowDQYJKoZIhvcNAQEL!LF!^
BQAwgY8xEzARBgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJkiaJk/IsZAEZFgdleGFt!LF!^
cGxlMRkwFwYDVQQKDBBFeGFtcGxlIENvbSBJbmMuMSEwHwYDVQQLDBhFeGFtcGxl!LF!^
IENvbSBJbmMuIFJvb3QgQ0ExITAfBgNVBAMMGEV4YW1wbGUgQ29tIEluYy4gUm9v!LF!^
dCBDQTAeFw0yMzA4MjkwNDIwMDNaFw0yMzA5MjgwNDIwMDNaMIGPMRMwEQYKCZIm!LF!^
iZPyLGQBGRYDY29tMRcwFQYKCZImiZPyLGQBGRYHZXhhbXBsZTEZMBcGA1UECgwQ!LF!^
RXhhbXBsZSBDb20gSW5jLjEhMB8GA1UECwwYRXhhbXBsZSBDb20gSW5jLiBSb290!LF!^
IENBMSEwHwYDVQQDDBhFeGFtcGxlIENvbSBJbmMuIFJvb3QgQ0EwggEiMA0GCSqG!LF!^
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDEPyN7J9VGPyJcQmCBl5TGwfSzvVdWwoQU!LF!^
j9aEsdfFJ6pBCDQSsj8Lv4RqL0dZra7h7SpZLLX/YZcnjikrYC+rP5OwsI9xEE/4!LF!^
U98CsTBPhIMgqFK6SzNE5494BsAk4cL72dOOc8tX19oDS/PvBULbNkthQ0aAF1dg!LF!^
vbrHvu7hq7LisB5ZRGHVE1k/AbCs2PaaKkn2jCw/b+U0Ml9qPuuEgz2mAqJDGYoA!LF!^
WSR4YXrOcrmPuRqbws464YZbJW898/0Pn/U300ed+4YHiNYLLJp51AMkR4YEw969!LF!^
VRPbWIvLrd0PQBooC/eLrL6rvud/GpYhdQEUx8qcNCKd4bz3OaQ5AgMBAAGjggEW!LF!^
MIIBEjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU!LF!^
F4ffoFrrZhKn1dD4uhJFPLcrAJwwgc8GA1UdIwSBxzCBxIAUF4ffoFrrZhKn1dD4!LF!^
uhJFPLcrAJyhgZWkgZIwgY8xEzARBgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJkiaJ!LF!^
k/IsZAEZFgdleGFtcGxlMRkwFwYDVQQKDBBFeGFtcGxlIENvbSBJbmMuMSEwHwYD!LF!^
VQQLDBhFeGFtcGxlIENvbSBJbmMuIFJvb3QgQ0ExITAfBgNVBAMMGEV4YW1wbGUg!LF!^
Q29tIEluYy4gUm9vdCBDQYIUd+SvPvzan5P2TQbEZ4zj4Gt6FYowDQYJKoZIhvcN!LF!^
AQELBQADggEBAIopqco/k9RSjouTeKP4z0EVUxdD4qnNh1GLSRqyAVe0aChyKF5f!LF!^
qt1Bd1XCY8D16RgekkKGHDpJhGCpel+vtIoXPBxUaGQNYxmJCf5OzLMODlcrZk5i!LF!^
jHIcv/FMeK02NBcz/WQ3mbWHVwXLhmwqa2zBsF4FmPCJAbFLchLhkAv1HJifHbnD!LF!^
jQzlKyl5jxam/wtjWxSm0iyso0z2TgyzY+MESqjEqB1hZkCFzD1xtUOCxbXgtKae!LF!^
dgfHVFuovr3fNLV3GvQk0s9okDwDUcqV7DSH61e5bUMfE84o3of8YA7+HUoPV5Du!LF!^
8sTOKRf7ncGXdDRA8aofW268pTCuIu3+g/Y=!LF!^
-----END CERTIFICATE-----!LF!


echo !ADMIN_CERT! > "%OPENSEARCH_CONF_DIR%kirk.pem"
echo !NODE_CERT! > "%OPENSEARCH_CONF_DIR%esnode.pem"
echo !ROOT_CA! > "%OPENSEARCH_CONF_DIR%root-ca.pem"
echo !NODE_KEY! > "%OPENSEARCH_CONF_DIR%esnode-key.pem"
echo !ADMIN_CERT_KEY! > "%OPENSEARCH_CONF_DIR%kirk-key.pem"

echo. >>  "%OPENSEARCH_CONF_FILE%"
echo ######## Start OpenSearch Security Demo Configuration ######## >> "%OPENSEARCH_CONF_FILE%"
echo # WARNING: revise all the lines below before you go into production >> "%OPENSEARCH_CONF_FILE%"
echo plugins.security.ssl.transport.pemcert_filepath: esnode.pem >> "%OPENSEARCH_CONF_FILE%"
echo plugins.security.ssl.transport.pemkey_filepath: esnode-key.pem >> "%OPENSEARCH_CONF_FILE%"
echo plugins.security.ssl.transport.pemtrustedcas_filepath: root-ca.pem >> "%OPENSEARCH_CONF_FILE%"
echo plugins.security.ssl.transport.enforce_hostname_verification: false >> "%OPENSEARCH_CONF_FILE%"
echo plugins.security.ssl.http.enabled: true >> "%OPENSEARCH_CONF_FILE%"
echo plugins.security.ssl.http.pemcert_filepath: esnode.pem >> "%OPENSEARCH_CONF_FILE%"
echo plugins.security.ssl.http.pemkey_filepath: esnode-key.pem >> "%OPENSEARCH_CONF_FILE%"
echo plugins.security.ssl.http.pemtrustedcas_filepath: root-ca.pem >> "%OPENSEARCH_CONF_FILE%"
echo plugins.security.allow_unsafe_democertificates: true >> "%OPENSEARCH_CONF_FILE%"
if %initsecurity% == 1 (
    echo plugins.security.allow_default_init_securityindex: true >> "%OPENSEARCH_CONF_FILE%"
)
echo plugins.security.authcz.admin_dn: >> "%OPENSEARCH_CONF_FILE%"
echo   - CN=kirk,OU=client,O=client,L=test, C=de >> "%OPENSEARCH_CONF_FILE%"
echo. >> "%OPENSEARCH_CONF_FILE%"
echo plugins.security.audit.type: internal_opensearch >> "%OPENSEARCH_CONF_FILE%"
echo plugins.security.enable_snapshot_restore_privilege: true >> "%OPENSEARCH_CONF_FILE%"
echo plugins.security.check_snapshot_restore_write_privileges: true >> "%OPENSEARCH_CONF_FILE%"
echo plugins.security.restapi.roles_enabled: ["all_access", "security_rest_api_access"] >> "%OPENSEARCH_CONF_FILE%"
echo plugins.security.system_indices.enabled: true >> "%OPENSEARCH_CONF_FILE%"
echo plugins.security.system_indices.indices: [".plugins-ml-config", ".plugins-ml-connector", ".plugins-ml-model-group", ".plugins-ml-model", ".plugins-ml-task", ".opendistro-alerting-config", ".opendistro-alerting-alert*", ".opendistro-anomaly-results*", ".opendistro-anomaly-detector*", ".opendistro-anomaly-checkpoints", ".opendistro-anomaly-detection-state", ".opendistro-reports-*", ".opensearch-notifications-*", ".opensearch-notebooks", ".opensearch-observability", ".ql-datasources", ".opendistro-asynchronous-search-response*", ".replication-metadata-store", ".opensearch-knn-models", ".geospatial-ip2geo-data*", ".opendistro-job-scheduler-lock"] >> "%OPENSEARCH_CONF_FILE%"

:: network.host
>nul findstr /b /c:"network.host" "%OPENSEARCH_CONF_FILE%" && (
    echo network.host already present
) || (
	if %cluster_mode% == 1 (
        echo network.host: 0.0.0.0 >> "%OPENSEARCH_CONF_FILE%"
        echo node.name: smoketestnode >> "%OPENSEARCH_CONF_FILE%"
        echo cluster.initial_cluster_manager_nodes: smoketestnode >> "%OPENSEARCH_CONF_FILE%"
    )
)

>nul findstr /b /c:"node.max_local_storage_nodes" "%OPENSEARCH_CONF_FILE%" && (
    echo node.max_local_storage_nodes already present
) || (
    echo node.max_local_storage_nodes: 3 >> "%OPENSEARCH_CONF_FILE%"
)

echo ######## End OpenSearch Security Demo Configuration ######## >> "%OPENSEARCH_CONF_FILE%"

echo ### Success
echo ### Execute this script now on all your nodes and then start all nodes
:: Generate securityadmin_demo.bat
echo. > securityadmin_demo.bat
echo %OPENSEARCH_PLUGINS_DIR%opensearch-security\tools\securityadmin.bat -cd %OPENSEARCH_CONF_DIR%opensearch-security -icl -key %OPENSEARCH_CONF_DIR%kirk-key.pem -cert %OPENSEARCH_CONF_DIR%kirk.pem -cacert %OPENSEARCH_CONF_DIR%root-ca.pem -nhnv >> securityadmin_demo.bat

if %initsecurity% == 0 (
	echo ### After the whole cluster is up execute: 
	type securityadmin_demo.bat
	echo ### or run ./securityadmin_demo.bat
    echo ### After that you can also use the Security Plugin ConfigurationGUI
) else (
    echo ### OpenSearch Security will be automatically initialized.
    echo ### If you like to change the runtime configuration 
    echo ### change the files in ../../../config/opensearch-security and execute: 
	type securityadmin_demo.bat
	echo ### or run ./securityadmin_demo.bat
	echo ### To use the Security Plugin ConfigurationGUI
)

echo ### To access your secured cluster open https://<hostname>:<HTTP port> and log in with admin/admin.
echo ### [Ignore the SSL certificate warning because we installed self-signed demo certificates]
