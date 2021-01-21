#!/usr/bin/env bash
export APPID=421799
#export SANDBOXID=537580
set -e
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR/..


if [ -z "$VERA_USER" ];then
	echo "No VERA_USER set"
	exit -1
fi

if [ -z "$VERA_PASSWORD" ];then
	echo "No VERA_PASSWORD set"
	exit -1
fi

echo "App Id: $APPID"
echo "Sandbox Id: $SANDBOXID"

echo "Build Security ..."
mvn clean package -Pveracode -DskipTests > /dev/null 2>&1
PLUGIN_FILE=($DIR/../target/veracode/opendistro-security*.zip)

FILESIZE=$(wc -c <"$PLUGIN_FILE")
echo ""
echo "Upload $PLUGIN_FILE with a size of $((FILESIZE / 1048576)) mb"


#curl -Ss --fail --compressed -u "$VERA_USER:$VERA_PASSWORD" https://analysiscenter.veracode.com/api/5.0/getapplist.do -F "include_user_info=true" | xmllint --format -
#curl -Ss --fail --compressed -u "$VERA_USER:$VERA_PASSWORD" https://analysiscenter.veracode.com/api/5.0/getsandboxlist.do -F "app_id=$APPID" | xmllint --format -
curl -Ss --fail --compressed -u "$VERA_USER:$VERA_PASSWORD" "https://analysiscenter.veracode.com/api/5.0/uploadfile.do" \
  -F "app_id=$APPID" \
  -F "file=@$PLUGIN_FILE" \
  -F "sandbox_id=$SANDBOXID" \
  | xmllint --format - 2>&1 | sed 's/.*<buildinfo\(.*\)buildinfo>.*/\1/' | tee  vera.log

echo ""
echo "Start pre scan"

#curl -Ss --fail --compressed -u "$VERA_USER:$VERA_PASSWORD"  https://analysiscenter.veracode.com/api/5.0/beginprescan.do -F "app_id=$APPID" -F "sandbox_id=$SANDBOXID" -F "auto_scan=false" | xmllint --format -
#curl -Ss --fail --compressed -u "$VERA_USER:$VERA_PASSWORD"  https://analysiscenter.veracode.com/api/5.0/getprescanresults.do -F "app_id=$APPID" -F "sandbox_id=$SANDBOXID" -F "build_id=2008250" | xmllint --format -

#curl -Ss --fail --compressed -u "$VERA_USER:$VERA_PASSWORD" "https://analysiscenter.veracode.com/api/5.0/beginscan.do" -F "app_id=$APPID" -F "sandbox_id=$SANDBOXID" -F "modules=932413446,932413464,932413518,932413454,932413453"

curl -Ss --fail --compressed -u "$VERA_USER:$VERA_PASSWORD"  https://analysiscenter.veracode.com/api/5.0/beginprescan.do -F "app_id=$APPID" -F "sandbox_id=$SANDBOXID" -F "auto_scan=true" -F "scan_all_nonfatal_top_level_modules=true" | xmllint --format -  2>&1 | sed 's/.*<buildinfo\(.*\)buildinfo>.*/\1/' | tee -a vera.log

echo ""
echo ""
echo "----- Veralog ------"
cat vera.log
echo "--------------------"
echo ""
echo ""
echo "Check for errors ..."
set +e
grep -i error vera.log && (echo "Error executing veracode"; exit -1)
grep -i denied vera.log && (echo "Access denied for veracode"; exit -1)
echo "No errors"
set -e

#curl -Ss --fail --compressed -u "$VERA_USER:$VERA_PASSWORD" "https://analysiscenter.veracode.com/api/5.0/beginscan.do" -F "app_id=$APPID" -F "sandbox_id=$SANDBOXID" -F "scan_all_top_level_modules=true" | xmllint --format -

#echo "Polling results"

#curl -Ss --fail --compressed -u "$VERA_USER:$VERA_PASSWORD"  https://analysiscenter.veracode.com/api/5.0/beginprescan.do -F "app_id=$APPID" -F "sandbox_id=$SANDBOXID" -F "auto_scan=true" -F "scan_all_nonfatal_top_level_modules=true" | xmllint --format -

#curl -Ss --fail --compressed -u "$VERA_USER:$VERA_PASSWORD"  https://analysiscenter.veracode.com/api/5.0/getbuildlist.do -F "app_id=$APPID" -F "sandbox_id=$SANDBOXID" | xmllint --format -
#curl --fail --compressed -k -v -u [api user] https://analysiscenter.veracode.com/api/5.0/detailedreport.do?build_id=49645c.

