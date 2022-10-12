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

echo "OpenSearch Security Demo Installer"
echo " ** Warning: Do not use on production or public reachable systems **"

set OPTIND=1
set assumeyes=0
set initsecurity=0
set cluster_mode=0
set skip_updates=-1

:show_help
echo "install_demo_configuration.bat [-y] [-i] [-c]"
echo "  -h show help"
echo "  -y confirm all installation dialogues automatically"
echo "  -i initialize Security plugin with default configuration (default is to ask if -y is not given)"
echo "  -c enable cluster mode by binding to all network interfaces (default is to ask if -y is not given)"
echo "  -s skip updates if config is already applied to opensearch.yml"
EXIT /B 0

:GETOPTS
 if /I "%1" == "-h" call :show_help & exit /b 0
 if /I "%1" == "-" set assumeyes=1
 if /I "%1" == "-i" set initsecurity=1
 if /I "%1" == "-c" set cluster_mode=1
 if /I "%1" == "-s" set skip_updates=0
 shift
if not "%1" == "" goto GETOPTS

if "%1" == "--" shift

if assumeyes == 0 (
    set /p "response=Install demo certificates? [Y/N] "
    if /I "%response%" neq "Y" exit /b 0
)

if initsecurity == 0 (
    if assumeyes == 0 (
        set /p "response=Initialize Security Modules? [Y/N] "
        if /I "%response%" eq "Y" initsecurity=1 ELSE initsecurity=0
    )
)

if cluster_mode == 0 (
    if assumeyes == 0 (
        echo "Cluster mode requires maybe additional setup of:"
        echo "  - Virtual memory (vm.max_map_count)"
        echo ""
        set /p "response=Enable cluster mode? [y/N] "
        if /I "%response%" eq "Y" cluster_mode=1 ELSE cluster_mode=0
    )
)

set BASE_DIR="%SCRIPT_DIR%\..\..\..\"
if exist BASE_DIR (
	set CUR="%cd%"
	cd "%BASE_DIR%"
	BASE_DIR="%cd%"
	cd "%CUR%"
	echo "Basedir: %BASE_DIR%"
) else (
    echo "DEBUG: basedir does not exist"
)
set OPENSEARCH_CONF_FILE="%BASE_DIR%\config\opensearch.yml"
set OPENSEARCH_CONF_DIR="%BASE_DIR%\config\"
set OPENSEARCH_BIN_DIR="%BASE_DIR%\bin"
set OPENSEARCH_PLUGINS_DIR="%BASE_DIR%\plugins\"
set OPENSEARCH_MODULES_DIR="%BASE_DIR%\modules\"
set OPENSEARCH_LIB_PATH="%BASE_DIR%\lib\"
set OPENSEARCH_INSTALL_TYPE=".tar.gz"

:: Check if its a rpm/deb install
if "/usr/share/opensearch" == "%BASE_DIR%" (
    set OPENSEARCH_CONF_FILE="/usr/share/opensearch/config/opensearch.yml"

    if not exist "%OPENSEARCH_CONF_FILE%" (
        set OPENSEARCH_CONF_FILE="/etc/opensearch/opensearch.yml"
        set OPENSEARCH_CONF_DIR="/etc/opensearch/"
    )

    set OPENSEARCH_INSTALL_TYPE="rpm/deb"
)

if not exist "%OPENSEARCH_CONF_FIL%" (
    echo "Unable to determine OpenSearch config directory. Quit."
    exit /b 1
)

if not exist "%OPENSEARCH_BIN_DIR%" (
	echo "Unable to determine OpenSearch bin directory. Quit."
	exit /b 1
)

if not exist "%OPENSEARCH_PLUGINS_DIR%" (
	echo "Unable to determine OpenSearch plugins directory. Quit."
	exit /b 1
)

if not exist "%OPENSEARCH_MODULES_DIR%" (
	echo "Unable to determine OpenSearch modules directory. Quit."
	:: exit /b 1
)

if not exist "%OPENSEARCH_LIB_PATH%" (
	echo "Unable to determine OpenSearch lib directory. Quit."
	exit /b 1
)

if not exist "%OPENSEARCH_PLUGINS_DIR%/opensearch-security" (
    echo "OpenSearch Security plugin not installed. Quit."
    exit /b 1
)

set "OPENSEARCH_VERSION="
for %%F in ("%OPENSEARCH_LIB_PATH%opensearch-*.jar") do set "OPENSEARCH_VERSION=%%~nxF"
echo "%OPENSEARCH_VERSION%"
set "OPENSEARCH_JAR_VERSION="
for /f "tokens=1,2,3 delims=[.]" %%a in ("%OPENSEARCH_VERSION%") Do Set "OPENSEARCH_JAR_VERSION=%%a.%%b.%%c" & exit /b

set "SECURITY_VERSION="
for %%F in ("%OPENSEARCH_PLUGINS_DIR%\opensearch-security\opensearch-security-*.jar") do set "SECURITY_VERSION=%%~nxF"
echo "%SECURITY_VERSION%"
set "SECURITY_JAR_VERSION="
for /f "tokens=1,2,3,4 delims=[.]" %%a in ("%SECURITY_VERSION%") Do Set "SECURITY_JAR_VERSION=%%a.%%b.%%c.%%d"

for /f "tokens=4-7 delims=[.] " %%i in ('ver') do (if %%i==Version (set OS=%%j.%%k) else (set v=%%i.%%j))
echo "OpenSearch install type: %OPENSEARCH_INSTALL_TYPE% on %OS%"
echo "OpenSearch config dir: %OPENSEARCH_CONF_DIR%"
echo "OpenSearch config file: %OPENSEARCH_CONF_FILE%"
echo "OpenSearch bin dir: %OPENSEARCH_BIN_DIR%"
echo "OpenSearch plugins dir: %OPENSEARCH_PLUGINS_DIR%"
echo "OpenSearch lib dir: %OPENSEARCH_LIB_PATH%"
echo "Detected OpenSearch Version: %OPENSEARCH_JAR_VERSION%"
echo "Detected OpenSearch Security Version: %SECURITY_JAR_VERSION%"

findstr /c:"plugins.security" "%OPENSEARCH_CONF_FILE%" && (
  echo "%OPENSEARCH_CONF_FILE% seems to be already configured for Security. Quit."
  exit /b %skip_updates%
)

set ADMIN_CERT=-----BEGIN CERTIFICATE-----^
MIIEdzCCA1+gAwIBAgIGAWLrc1O4MA0GCSqGSIb3DQEBCwUAMIGPMRMwEQYKCZIm^
iZPyLGQBGRYDY29tMRcwFQYKCZImiZPyLGQBGRYHZXhhbXBsZTEZMBcGA1UECgwQ^
RXhhbXBsZSBDb20gSW5jLjEhMB8GA1UECwwYRXhhbXBsZSBDb20gSW5jLiBSb290^
IENBMSEwHwYDVQQDDBhFeGFtcGxlIENvbSBJbmMuIFJvb3QgQ0EwHhcNMTgwNDIy^
MDM0MzQ3WhcNMjgwNDE5MDM0MzQ3WjBNMQswCQYDVQQGEwJkZTENMAsGA1UEBwwE^
dGVzdDEPMA0GA1UECgwGY2xpZW50MQ8wDQYDVQQLDAZjbGllbnQxDTALBgNVBAMM^
BGtpcmswggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCwgBOoO88uMM8^
dREJsk58Yt4Jn0zwQ2wUThbvy3ICDiEWhiAhUbg6dTggpS5vWWJto9bvaaqgMVoh^
ElfYHdTDncX3UQNBEP8tqzHON6BFEFSGgJRGLd6f5dri6rK32nCotYS61CFXBFxf^
WumXjSukjyrcTsdkR3C5QDo2oN7F883MOQqRENPzAtZi9s3jNX48u+/e3yvJzXsB^
GS9Qmsye6C71enbIujM4CVwDT/7a5jHuaUp6OuNCFbdRPnu/wLYwOS2/yOtzAqk7^
/PFnPCe7YOa10ShnV/jx2sAHhp7ZQBJgFkkgnIERz9Ws74Au+EbptWnsWuB+LqRL^
x5G02IzpAgMBAAGjggEYMIIBFDCBvAYDVR0jBIG0MIGxgBSSNQzgDx4rRfZNOfN7^
X6LmEpdAc6GBlaSBkjCBjzETMBEGCgmSJomT8ixkARkWA2NvbTEXMBUGCgmSJomT^
8ixkARkWB2V4YW1wbGUxGTAXBgNVBAoMEEV4YW1wbGUgQ29tIEluYy4xITAfBgNV^
BAsMGEV4YW1wbGUgQ29tIEluYy4gUm9vdCBDQTEhMB8GA1UEAwwYRXhhbXBsZSBD^
b20gSW5jLiBSb290IENBggEBMB0GA1UdDgQWBBRsdhuHn3MGDvZxOe22+1wliCJB^
mDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIF4DAWBgNVHSUBAf8EDDAKBggr^
BgEFBQcDAjANBgkqhkiG9w0BAQsFAAOCAQEAkPrUTKKn+/6g0CjhTPBFeX8mKXhG^
zw5z9Oq+xnwefZwxV82E/tgFsPcwXcJIBg0f43BaVSygPiV7bXqWhxASwn73i24z^
lveIR4+z56bKIhP6c3twb8WWR9yDcLu2Iroin7dYEm3dfVUrhz/A90WHr6ddwmLL^
3gcFF2kBu3S3xqM5OmN/tqRXFmo+EvwrdJRiTh4Fsf0tX1ZT07rrGvBFYktK7Kma^
lqDl4UDCF1UWkiiFubc0Xw+DR6vNAa99E0oaphzvCmITU1wITNnYZTKzVzQ7vUCq^
kLmXOFLTcxTQpptxSo5xDD3aTpzWGCvjExCKpXQtsITUOYtZc02AGjjPOQ==^
-----END CERTIFICATE-----

echo "%ADMIN_CERT%"

set ADMIN_CERT_KEY=-----BEGIN PRIVATE KEY-----^
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDCwgBOoO88uMM8^
dREJsk58Yt4Jn0zwQ2wUThbvy3ICDiEWhiAhUbg6dTggpS5vWWJto9bvaaqgMVoh^
ElfYHdTDncX3UQNBEP8tqzHON6BFEFSGgJRGLd6f5dri6rK32nCotYS61CFXBFxf^
WumXjSukjyrcTsdkR3C5QDo2oN7F883MOQqRENPzAtZi9s3jNX48u+/e3yvJzXsB^
GS9Qmsye6C71enbIujM4CVwDT/7a5jHuaUp6OuNCFbdRPnu/wLYwOS2/yOtzAqk7^
/PFnPCe7YOa10ShnV/jx2sAHhp7ZQBJgFkkgnIERz9Ws74Au+EbptWnsWuB+LqRL^
x5G02IzpAgMBAAECggEAEzwnMkeBbqqDgyRqFbO/PgMNvD7i0b/28V0dCtCPEVY6^
klzrg3RCERP5V9AN8VVkppYjPkCzZ2A4b0JpMUu7ncOmr7HCnoSCj2IfEyePSVg+^
4OHbbcBOAoDTHiI2myM/M9++8izNS34qGV4t6pfjaDyeQQ/5cBVWNBWnKjS34S5H^
rJWpAcDgxYk5/ah2Xs2aULZlXDMxbSikjrv+n4JIYTKFQo8ydzL8HQDBRmXAFLjC^
gNOSHf+5u1JdpY3uPIxK1ugVf8zPZ4/OEB23j56uu7c8+sZ+kZwfRWAQmMhFVG/y^
OXxoT5mOruBsAw29m2Ijtxg252/YzSTxiDqFziB/eQKBgQDjeVAdi55GW/bvhuqn^
xME/An8E3hI/FyaaITrMQJUBjiCUaStTEqUgQ6A7ZfY/VX6qafOX7sli1svihrXC^
uelmKrdve/CFEEqzX9JWWRiPiQ0VZD+EQRsJvX85Tw2UGvVUh6dO3UGPS0BhplMD^
jeVpyXgZ7Gy5we+DWjfwhYrCmwKBgQDbLmQhRy+IdVljObZmv3QtJ0cyxxZETWzU^
MKmgBFvcRw+KvNwO+Iy0CHEbDu06Uj63kzI2bK3QdINaSrjgr8iftXIQpBmcgMF+^
a1l5HtHlCp6RWd55nWQOEvn36IGN3cAaQkXuh4UYM7QfEJaAbzJhyJ+wXA3jWqUd^
8bDTIAZ0ywKBgFuZ44gyTAc7S2JDa0Up90O/ZpT4NFLRqMrSbNIJg7d/m2EIRNkM^
HhCzCthAg/wXGo3XYq+hCdnSc4ICCzmiEfoBY6LyPvXmjJ5VDOeWs0xBvVIK74T7^
jr7KX2wdiHNGs9pZUidw89CXVhK8nptEzcheyA1wZowbK68yamph7HHXAoGBAK3x^
7D9Iyl1mnDEWPT7f1Gh9UpDm1TIRrDvd/tBihTCVKK13YsFy2d+LD5Bk0TpGyUVR^
STlOGMdloFUJFh4jA3pUOpkgUr8Uo/sbYN+x6Ov3+I3sH5aupRhSURVA7YhUIz/z^
tqIt5R+m8Nzygi6dkQNvf+Qruk3jw0S3ahizwsvvAoGAL7do6dTLp832wFVxkEf4^
gg1M6DswfkgML5V/7GQ3MkIX/Hrmiu+qSuHhDGrp9inZdCDDYg5+uy1+2+RBMRZ3^
vDUUacvc4Fep05zp7NcjgU5y+/HWpuKVvLIlZAO1MBY4Xinqqii6RdxukIhxw7eT^
C6TPL5KAcV1R/XAihDhI18Y=^
-----END PRIVATE KEY-----

set NODE_CERT=-----BEGIN CERTIFICATE-----^
MIIEyTCCA7GgAwIBAgIGAWLrc1O2MA0GCSqGSIb3DQEBCwUAMIGPMRMwEQYKCZIm^
iZPyLGQBGRYDY29tMRcwFQYKCZImiZPyLGQBGRYHZXhhbXBsZTEZMBcGA1UECgwQ^
RXhhbXBsZSBDb20gSW5jLjEhMB8GA1UECwwYRXhhbXBsZSBDb20gSW5jLiBSb290^
IENBMSEwHwYDVQQDDBhFeGFtcGxlIENvbSBJbmMuIFJvb3QgQ0EwHhcNMTgwNDIy^
MDM0MzQ3WhcNMjgwNDE5MDM0MzQ3WjBeMRIwEAYKCZImiZPyLGQBGRYCZGUxDTAL^
BgNVBAcMBHRlc3QxDTALBgNVBAoMBG5vZGUxDTALBgNVBAsMBG5vZGUxGzAZBgNV^
BAMMEm5vZGUtMC5leGFtcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC^
AQoCggEBAJa+f476vLB+AwK53biYByUwN+40D8jMIovGXm6wgT8+9Sbs899dDXgt^
9CE1Beo65oP1+JUz4c7UHMrCY3ePiDt4cidHVzEQ2g0YoVrQWv0RedS/yx/DKhs8^
Pw1O715oftP53p/2ijD5DifFv1eKfkhFH+lwny/vMSNxellpl6NxJTiJVnQ9HYOL^
gf2t971ITJHnAuuxUF48HcuNovW4rhtkXef8kaAN7cE3LU+A9T474ULNCKkEFPIl^
ZAKN3iJNFdVsxrTU+CUBHzk73Do1cCkEvJZ0ZFjp0Z3y8wLY/gqWGfGVyA9l2CUq^
eIZNf55PNPtGzOrvvONiui48vBKH1LsCAwEAAaOCAVkwggFVMIG8BgNVHSMEgbQw^
gbGAFJI1DOAPHitF9k0583tfouYSl0BzoYGVpIGSMIGPMRMwEQYKCZImiZPyLGQB^
GRYDY29tMRcwFQYKCZImiZPyLGQBGRYHZXhhbXBsZTEZMBcGA1UECgwQRXhhbXBs^
ZSBDb20gSW5jLjEhMB8GA1UECwwYRXhhbXBsZSBDb20gSW5jLiBSb290IENBMSEw^
HwYDVQQDDBhFeGFtcGxlIENvbSBJbmMuIFJvb3QgQ0GCAQEwHQYDVR0OBBYEFKyv^
78ZmFjVKM9g7pMConYH7FVBHMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgXg^
MCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjA1BgNVHREELjAsiAUq^
AwQFBYISbm9kZS0wLmV4YW1wbGUuY29tgglsb2NhbGhvc3SHBH8AAAEwDQYJKoZI^
hvcNAQELBQADggEBAIOKuyXsFfGv1hI/Lkpd/73QNqjqJdxQclX57GOMWNbOM5H0^
5/9AOIZ5JQsWULNKN77aHjLRr4owq2jGbpc/Z6kAd+eiatkcpnbtbGrhKpOtoEZy^
8KuslwkeixpzLDNISSbkeLpXz4xJI1ETMN/VG8ZZP1bjzlHziHHDu0JNZ6TnNzKr^
XzCGMCohFfem8vnKNnKUneMQMvXd3rzUaAgvtf7Hc2LTBlf4fZzZF1EkwdSXhaMA^
1lkfHiqOBxtgeDLxCHESZ2fqgVqsWX+t3qHQfivcPW6txtDyrFPRdJOGhiMGzT/t^
e/9kkAtQRgpTb3skYdIOOUOV0WGQ60kJlFhAzIs=^
-----END CERTIFICATE-----

set NODE_KEY=-----BEGIN PRIVATE KEY-----^
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCWvn+O+rywfgMC^
ud24mAclMDfuNA/IzCKLxl5usIE/PvUm7PPfXQ14LfQhNQXqOuaD9fiVM+HO1BzK^
wmN3j4g7eHInR1cxENoNGKFa0Fr9EXnUv8sfwyobPD8NTu9eaH7T+d6f9oow+Q4n^
xb9Xin5IRR/pcJ8v7zEjcXpZaZejcSU4iVZ0PR2Di4H9rfe9SEyR5wLrsVBePB3L^
jaL1uK4bZF3n/JGgDe3BNy1PgPU+O+FCzQipBBTyJWQCjd4iTRXVbMa01PglAR85^
O9w6NXApBLyWdGRY6dGd8vMC2P4KlhnxlcgPZdglKniGTX+eTzT7Rszq77zjYrou^
PLwSh9S7AgMBAAECggEABwiohxFoEIwws8XcdKqTWsbfNTw0qFfuHLuK2Htf7IWR^
htlzn66F3F+4jnwc5IsPCoVFriCXnsEC/usHHSMTZkL+gJqxlNaGdin6DXS/aiOQ^
nb69SaQfqNmsz4ApZyxVDqsQGkK0vAhDAtQVU45gyhp/nLLmmqP8lPzMirOEodmp^
U9bA8t/ttrzng7SVAER42f6IVpW0iTKTLyFii0WZbq+ObViyqib9hVFrI6NJuQS+^
IelcZB0KsSi6rqIjXg1XXyMiIUcSlhq+GfEa18AYgmsbPwMbExate7/8Ci7ZtCbh^
lx9bves2+eeqq5EMm3sMHyhdcg61yzd5UYXeZhwJkQKBgQDS9YqrAtztvLY2gMgv^
d+wOjb9awWxYbQTBjx33kf66W+pJ+2j8bI/XX2CpZ98w/oq8VhMqbr9j5b8MfsrF^
EoQvedA4joUo8sXd4j1mR2qKF4/KLmkgy6YYusNP2UrVSw7sh77bzce+YaVVoO/e^
0wIVTHuD/QZ6fG6MasOqcbl6hwKBgQC27cQruaHFEXR/16LrMVAX+HyEEv44KOCZ^
ij5OE4P7F0twb+okngG26+OJV3BtqXf0ULlXJ+YGwXCRf6zUZkld3NMy3bbKPgH6^
H/nf3BxqS2tudj7+DV52jKtisBghdvtlKs56oc9AAuwOs37DvhptBKUPdzDDqfys^
Qchv5JQdLQKBgERev+pcqy2Bk6xmYHrB6wdseS/4sByYeIoi0BuEfYH4eB4yFPx6^
UsQCbVl6CKPgWyZe3ydJbU37D8gE78KfFagtWoZ56j4zMF2RDUUwsB7BNCDamce/^
OL2bCeG/Erm98cBG3lxufOX+z47I8fTNfkdY2k8UmhzoZwurLm73HJ3RAoGBAKsp^
6yamuXF2FbYRhUXgjHsBbTD/vJO72/yO2CGiLRpi/5mjfkjo99269trp0C8sJSub^
5PBiSuADXFsoRgUv+HI1UAEGaCTwxFTQWrRWdtgW3d0sE2EQDVWL5kmfT9TwSeat^
mSoyAYR5t3tCBNkPJhbgA7pm4mASzHQ50VyxWs25AoGBAKPFx9X2oKhYQa+mW541^
bbqRuGFMoXIIcr/aeM3LayfLETi48o5NDr2NDP11j4yYuz26YLH0Dj8aKpWuehuH^
uB27n6j6qu0SVhQi6mMJBe1JrKbzhqMKQjYOoy8VsC2gdj5pCUP/kLQPW7zm9diX^
CiKTtKgPIeYdigor7V3AHcVT^
-----END PRIVATE KEY-----

set ROOT_CA=-----BEGIN CERTIFICATE-----^
MIID/jCCAuagAwIBAgIBATANBgkqhkiG9w0BAQsFADCBjzETMBEGCgmSJomT8ixk^
ARkWA2NvbTEXMBUGCgmSJomT8ixkARkWB2V4YW1wbGUxGTAXBgNVBAoMEEV4YW1w^
bGUgQ29tIEluYy4xITAfBgNVBAsMGEV4YW1wbGUgQ29tIEluYy4gUm9vdCBDQTEh^
MB8GA1UEAwwYRXhhbXBsZSBDb20gSW5jLiBSb290IENBMB4XDTE4MDQyMjAzNDM0^
NloXDTI4MDQxOTAzNDM0NlowgY8xEzARBgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJ^
kiaJk/IsZAEZFgdleGFtcGxlMRkwFwYDVQQKDBBFeGFtcGxlIENvbSBJbmMuMSEw^
HwYDVQQLDBhFeGFtcGxlIENvbSBJbmMuIFJvb3QgQ0ExITAfBgNVBAMMGEV4YW1w^
bGUgQ29tIEluYy4gUm9vdCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC^
ggEBAK/u+GARP5innhpXK0c0q7s1Su1VTEaIgmZr8VWI6S8amf5cU3ktV7WT9SuV^
TsAm2i2A5P+Ctw7iZkfnHWlsC3HhPUcd6mvzGZ4moxnamM7r+a9otRp3owYoGStX^
ylVTQusAjbq9do8CMV4hcBTepCd+0w0v4h6UlXU8xjhj1xeUIz4DKbRgf36q0rv4^
VIX46X72rMJSETKOSxuwLkov1ZOVbfSlPaygXIxqsHVlj1iMkYRbQmaTib6XWHKf^
MibDaqDejOhukkCjzpptGZOPFQ8002UtTTNv1TiaKxkjMQJNwz6jfZ53ws3fh1I0^
RWT6WfM4oeFRFnyFRmc4uYTUgAkCAwEAAaNjMGEwDwYDVR0TAQH/BAUwAwEB/zAf^
BgNVHSMEGDAWgBSSNQzgDx4rRfZNOfN7X6LmEpdAczAdBgNVHQ4EFgQUkjUM4A8e^
K0X2TTnze1+i5hKXQHMwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBCwUAA4IB^
AQBoQHvwsR34hGO2m8qVR9nQ5Klo5HYPyd6ySKNcT36OZ4AQfaCGsk+SecTi35QF^
RHL3g2qffED4tKR0RBNGQSgiLavmHGCh3YpDupKq2xhhEeS9oBmQzxanFwWFod4T^
nnsG2cCejyR9WXoRzHisw0KJWeuNlwjUdJY0xnn16srm1zL/M/f0PvCyh9HU1mF1^
ivnOSqbDD2Z7JSGyckgKad1Omsg/rr5XYtCeyJeXUPcmpeX6erWJJNTUh6yWC/hY^
G/dFC4xrJhfXwz6Z0ytUygJO32bJG4Np2iGAwvvgI9EfxzEv/KP+FGrJOvQJAq4/^
BU36ZAa80W/8TBnqZTkNnqZV^
-----END CERTIFICATE-----

echo %ADMIN_CERT% > "%OPENSEARCH_CONF_DIR%kirk.pem"
echo %NODE_CERT% > "%OPENSEARCH_CONF_DIR%esnode.pem"
echo %ROOT_CA% > "%OPENSEARCH_CONF_DIR%root-ca.pem"
echo %NODE_KEY% > "%OPENSEARCH_CONF_DIR%esnode-key.pem"
echo %ADMIN_CERT_KEY% > "%OPENSEARCH_CONF_DIR%kirk-key.pem"

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
if initsecurity == 1 (
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
echo plugins.security.system_indices.indices: [".plugins-ml-model", ".plugins-ml-task", ".opendistro-alerting-config", ".opendistro-alerting-alert*", ".opendistro-anomaly-results*", ".opendistro-anomaly-detector*", ".opendistro-anomaly-checkpoints", ".opendistro-anomaly-detection-state", ".opendistro-reports-*", ".opensearch-notifications-*", ".opensearch-notebooks", ".opensearch-observability", ".opendistro-asynchronous-search-response*", ".replication-metadata-store"] >> "%OPENSEARCH_CONF_FILE%"

:: network.host
findstr /b /c:"network.host" "%OPENSEARCH_CONF_FILE%" && (
    :: #already present
) || (
	if cluster_mode == 1 (
        echo network.host: 0.0.0.0 >> "%OPENSEARCH_CONF_FILE%"
        echo node.name: smoketestnode >> "%OPENSEARCH_CONF_FILE%"
        echo cluster.initial_cluster_manager_nodes: smoketestnode >> "%OPENSEARCH_CONF_FILE%"
    )
)

findstr /b /c:"node.max_local_storage_nodes" "%OPENSEARCH_CONF_FILE%" && (
    :: #already present
) || (
    echo node.max_local_storage_nodes: 3 >> "%OPENSEARCH_CONF_FILE%"
)

echo ######## End OpenSearch Security Demo Configuration ######## >> "%OPENSEARCH_CONF_FILE%"

echo ### Success
echo ### Execute this script now on all your nodes and then start all nodes
:: Generate securityadmin_demo.bat
echo "" >> securityadmin_demo.bat
echo %OPENSEARCH_PLUGINS_DIR%opensearch-security\tools\securityadmin.bat -cd %OPENSEARCH_CONF_DIR%opensearch-security -icl -key %OPENSEARCH_CONF_DIR%kirk-key.pem -cert %OPENSEARCH_CONF_DIR%kirk.pem -cacert %OPENSEARCH_CONF_DIR%root-ca.pem -nhnv >> securityadmin_demo.sh

if initsecurity == 0 (
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
echo ### (Ignore the SSL certificate warning because we installed self-signed demo certificates)
