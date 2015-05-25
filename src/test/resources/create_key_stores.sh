rm -f Searchguard*.jks
rm -f searchguard*.pem

keytool -keystore SearchguardKS.jks -genkey -v -validity 7200 -keyalg RSA -keypass changeit -storepass changeit -alias searchguard -dname "CN=localhost, OU=Searchguard, O=Test, L=Test, C=DE"
keytool -keystore SearchguardFailKS.jks -genkey -v -validity 7200 -keyalg RSA -keypass changeit -storepass changeit -alias searchguardfail -dname "CN=localhost, OU=Searchguardfail, O=Test, L=Test, C=DE"

keytool -keystore SearchguardKS.jks -selfcert -v -alias searchguard -storepass changeit
keytool -keystore SearchguardFailKS.jks -selfcert -v -alias searchguardfail -storepass changeit

keytool -keystore SearchguardKS.jks -export -v -keypass changeit -storepass changeit -rfc -alias searchguard -file searchguard.pem
keytool -keystore SearchguardFailKS.jks -export -v -keypass changeit -storepass changeit -rfc -alias searchguardfail -file searchguardfail.pem

keytool -keystore SearchguardTS.jks -import -noprompt  -v -keypass changeit -storepass changeit -alias searchguard -file searchguard.pem