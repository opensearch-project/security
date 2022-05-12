/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Portions Copyright OpenSearch Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package org.opensearch.security.tools;

import java.io.Console;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;

import com.fasterxml.jackson.databind.InjectableValues;
import com.fasterxml.jackson.databind.JsonNode;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.http.HttpHost;
import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.nio.conn.ssl.SSLIOSessionStrategy;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;

import org.opensearch.action.admin.cluster.health.ClusterHealthRequest;
import org.opensearch.action.admin.cluster.health.ClusterHealthResponse;
import org.opensearch.client.Request;
import org.opensearch.client.RequestOptions;
import org.opensearch.client.Response;
import org.opensearch.client.RestClient;
import org.opensearch.client.RestClientBuilder;
import org.opensearch.client.RestHighLevelClient;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.NonValidatingObjectMapper;
import org.opensearch.security.ssl.util.ExceptionUtils;
import org.opensearch.security.support.PemKeyReader;

public class PasswordSetup extends Command {
    private static final String OPENDISTRO_SECURITY_TS_PASS = "OPENDISTRO_SECURITY_TS_PASS";
    private static final String OPENDISTRO_SECURITY_KS_PASS = "OPENDISTRO_SECURITY_KS_PASS";
    private static final String OPENDISTRO_SECURITY_KEYPASS = "OPENDISTRO_SECURITY_KEYPASS";
    private static final String DEFAULT_HOSTNAME = "localhost";
    private static final String DEFAULT_CLUSTER_NAME = "opensearch";
    private static final int DEFAULT_PORT = 9200;
    private static final String DEFAULT_CONFIG_DIR = "../../../config/";
    private static final ArrayList<String> INBUILT_USERS_LIST = new ArrayList<String>(Arrays.asList("admin", "kibanaserver", "kibanaro", "logstash", "readall", "snapshotrestore"));
    private static Options options = new Options();

    public PasswordSetup() {
        options.addOption( "nhnv", "disable-host-name-verification", false, "Disable hostname verification" );

        options.addOption(Option.builder("ts").longOpt("truststore").hasArg().argName("file").desc("Path to truststore (JKS/PKCS12 format)").build());
        options.addOption(Option.builder("ks").longOpt("keystore").hasArg().argName("file").desc("Path to keystore (JKS/PKCS12 format").build());
        options.addOption(Option.builder("tst").longOpt("truststore-type").hasArg().argName("type").desc("JKS or PKCS12, if not given we use the file extension to dectect the type").build());
        options.addOption(Option.builder("kst").longOpt("keystore-type").hasArg().argName("type").desc("JKS or PKCS12, if not given we use the file extension to dectect the type").build());
        options.addOption(Option.builder("tspass").longOpt("truststore-password").hasArg().argName("password").desc("Truststore password").build());
        options.addOption(Option.builder("kspass").longOpt("keystore-password").hasArg().argName("password").desc("Keystore password").build());
        options.addOption(Option.builder("cacert").hasArg().argName("file").desc("Path to trusted cacert (PEM format)").build());
        options.addOption(Option.builder("cert").hasArg().argName("file").desc("Path to admin certificate in PEM format").build());
        options.addOption(Option.builder("key").hasArg().argName("file").desc("Path to the key of admin certificate").build());
        options.addOption(Option.builder("keypass").hasArg().argName("password").desc("Password of the key of admin certificate (optional)").build());

        options.addOption(Option.builder("cd").longOpt("configdir").hasArg().argName("directory").desc("Directory for config files").build());
        options.addOption(Option.builder("h").longOpt("hostname").hasArg().argName("host").desc("OpenSearch host (default: localhost)").build());
        options.addOption(Option.builder("p").longOpt("port").hasArg().argName("port").desc("OpenSearch transport port (default: 9200)").build());
        options.addOption(Option.builder("cn").longOpt("clustername").hasArg().argName("clustername").desc("Clustername (do not use together with -icl)").build());
        options.addOption( "icl", "ignore-clustername", false, "Ignore clustername (do not use together with -cn)" );
        options.addOption(Option.builder("ksalias").longOpt("keystore-alias").hasArg().argName("alias").desc("Keystore alias").build());
        options.addOption(Option.builder("auto").longOpt("auto-generate-passwords").desc("Auto-generate passwords for in-built users").build());
    }

    public String describe() {
        return "Helps setting passwords for built-in users";
    }

    public void usage() {
        final HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("opensearch-admin.sh", options, true);
    }

    public int execute(final String[] args) throws Exception {
        String hostname;
        String cacert;
        String cert;
        String key;
        String clustername;
        String cd;
        int port;
        String ks = null;
        String ts = null;
        String kst = null;
        String tst = null;

        String kspass = System.getenv(OPENDISTRO_SECURITY_KS_PASS);
        String tspass = System.getenv(OPENDISTRO_SECURITY_TS_PASS);
        boolean nhnv = false;
        String ksAlias = null;
        String[] enabledProtocols = new String[0];
        String[] enabledCiphers = new String[0];
        boolean autoGenerate = false;
        
        String keypass = System.getenv(OPENDISTRO_SECURITY_KEYPASS);
        final boolean promptForPassword;

        InjectableValues.Std injectableValues = new InjectableValues.Std();
        injectableValues.addValue(Settings.class, Settings.builder().build());
        DefaultObjectMapper.inject(injectableValues);
        NonValidatingObjectMapper.inject(injectableValues);

        CommandLineParser parser = new DefaultParser();
        try {
            CommandLine line = parser.parse( options, args );
            validate(line);

            hostname = line.getOptionValue("h", DEFAULT_HOSTNAME);
            port = Integer.parseInt(line.getOptionValue("p", String.valueOf(DEFAULT_PORT)));
            promptForPassword = line.hasOption("prompt");
            
            if(kspass == null || kspass.isEmpty()) {
                kspass = line.getOptionValue("kspass",promptForPassword?null:"changeit");
            }
            
            if(tspass == null || tspass.isEmpty()) {
                tspass = line.getOptionValue("tspass",promptForPassword?null:kspass);
            }

            cd = line.getOptionValue("cd", DEFAULT_CONFIG_DIR);
            if(!cd.endsWith(File.separator)) {
                cd += File.separator;
            }

            ks = line.getOptionValue("ks",ks);
            ts = line.getOptionValue("ts",ts);
            kst = line.getOptionValue("kst", kst);
            tst = line.getOptionValue("tst", tst);
            nhnv = line.hasOption("nhnv");
            clustername = line.getOptionValue("cn", DEFAULT_CLUSTER_NAME);
            ksAlias = line.getOptionValue("ksalias", ksAlias);
            String enabledCiphersString = line.getOptionValue("ec", null);
            String enabledProtocolsString = line.getOptionValue("ep", null);
            
            if(enabledCiphersString != null) {
                enabledCiphers = enabledCiphersString.split(",");
            }
            
            if(enabledProtocolsString != null) {
                enabledProtocols = enabledProtocolsString.split(",");
            }

            autoGenerate = line.hasOption("auto");
            
            cacert = line.getOptionValue("cacert", DEFAULT_CONFIG_DIR + "root-ca.pem");
            cert = line.getOptionValue("cert", DEFAULT_CONFIG_DIR + "kirk.pem");
            key = line.getOptionValue("key", DEFAULT_CONFIG_DIR + "kirk-key.pem");
            keypass = line.getOptionValue("keypass", keypass);
        }
        catch( ParseException exp ) {
            System.out.println("ERR: Parsing failed.  Reason: " + exp.getMessage());
            usage();
            return -1;
        }

        if(ks != null) {
            kst = kst==null?(ks.endsWith(".jks")?"JKS":"PKCS12"):kst;
            if(kspass == null && promptForPassword) {
                kspass = promptForPassword("Keystore", "kspass", OPENDISTRO_SECURITY_KS_PASS);
            }
        }
        
        if(ts != null) {
            tst = tst==null?(ts.endsWith(".jks")?"JKS":"PKCS12"):tst;
            if(tspass == null && promptForPassword) {
                tspass = promptForPassword("Truststore", "tspass", OPENDISTRO_SECURITY_TS_PASS);
            }
        }            

        if(key != null) {
            if(keypass == null && promptForPassword) {
                keypass = promptForPassword("Pemkey", "keypass", OPENDISTRO_SECURITY_KEYPASS);
            }
        }
        
        final SSLContext sslContext = sslContext(ts, tspass, tst, ks, kspass, kst, ksAlias, cacert, cert, key, keypass);
        System.out.println(String.format("Connecting to %s:%s", hostname, port));
        try (RestHighLevelClient restHighLevelClient = getRestHighLevelClient(sslContext, nhnv, enabledProtocols, enabledCiphers, hostname, port)) {
            RestClient lowLevelClient = restHighLevelClient.getLowLevelClient();
            if(!isAdminUser(lowLevelClient)) {
                return -1;
            }

			try {
			    waitForClusterStatus(restHighLevelClient);
            } catch (TimeoutException e) {
                System.out.println("ERR: Timed out while waiting for a green or yellow cluster state.");
                System.out.println("   * Try running opensearch-admin.sh with -icl (but no -cl) and -nhnv (If that works you need to check your clustername as well as hostnames in your TLS certificates)");
                System.out.println("   * Make also sure that your keystore or PEM certificate is a client certificate (not a node certificate) and configured properly in opensearch.yml");
                return -1;
            }

			setupPasswordForInbuiltUsers(lowLevelClient, autoGenerate);
        } catch (Throwable e) {
            System.out.println(e);
            return -1;
        }
        return 0;
    }

    private static void setupPasswordForInbuiltUsers(RestClient lowLevelClient, boolean autoGenerate) throws Exception {
        System.out.println("\n\nBeginning Password Setup\n");

        if (autoGenerate) {
            System.out.println("Disclaimer: You may have to escape special characters when accessing cluster");
            for (String user: INBUILT_USERS_LIST) {
                String password = createPassword();
                System.out.println("\nPassword for " + user + " is: " + password);
                setPasswordSingleUser(user, lowLevelClient, password);
            }
        } else {
            Scanner sc = new Scanner(System.in);
            System.out.println("Disclaimer: Use an escape sequence character when using \\.  Example: If your password is Abcd\\efg!, then the input should be Abcd\\\\efg!");
            for (String user: INBUILT_USERS_LIST) {
                System.out.println("\nEnter password for " + user + ": ");
                String password = sc.nextLine();
                setPasswordSingleUser(user, lowLevelClient, password);
                System.out.println("Done setting password for " + user);
            }
            sc.close();
        }
    }

    private static void waitForClusterStatus(RestHighLevelClient restHighLevelClient) throws Exception {
        System.out.println(String.format("Waiting for YELLOW cluster state"));
        ClusterHealthResponse chResponse = null;
        while (chResponse == null) {
            try {
                final ClusterHealthRequest chRequest = new ClusterHealthRequest().timeout(TimeValue.timeValueMinutes(5));
                chRequest.waitForYellowStatus();
                chResponse = restHighLevelClient.cluster().health(chRequest, RequestOptions.DEFAULT);
            } catch (Exception e) {
                Throwable rootCause = ExceptionUtils.getRootCause(e);
                System.out.println("Cannot retrieve cluster state due to: "+e.getMessage()+". This is not an error, will keep on trying ...");
                System.out.println("  Root cause: "+rootCause+" ("+e.getClass().getName()+"/"+rootCause.getClass().getName()+")");
                Thread.sleep(3000);
                continue;
            }

            final boolean timedOut = chResponse.isTimedOut();
            if (timedOut) {
                System.out.println("ERR: Timed out while waiting for a green or yellow cluster state.");
                System.out.println("   * Try running opensearch-admin.sh with -icl (but no -cl) and -nhnv (If that works you need to check your clustername as well as hostnames in your TLS certificates)");
                System.out.println("   * Make also sure that your keystore or PEM certificate is a client certificate (not a node certificate) and configured properly in opensearch.yml");
                throw new TimeoutException();
            }
        }
    }

    private static boolean isAdminUser(RestClient lowLevelClient) throws IOException {
        Response whoAmIRes = lowLevelClient.performRequest(new Request("GET", "/_plugins/_security/whoami"));

        if (whoAmIRes.getStatusLine().getStatusCode() != 200) {
            throw new IOException("Unable to check whether cluster is sane because return code was " + whoAmIRes.getStatusLine());
        }

        JsonNode whoAmIResNode = DefaultObjectMapper.objectMapper.readTree(whoAmIRes.getEntity().getContent());
        System.out.println("Connected as " + whoAmIResNode.get("dn"));

        if (!whoAmIResNode.get("is_admin").asBoolean()) {

            System.out.println("ERR: " + whoAmIResNode.get("dn") + " is not an admin user");

            if (!whoAmIResNode.get("is_node_certificate_request").asBoolean()) {
                System.out.println("Seems you use a client certificate but this one is not registered as admin_dn");
                System.out.println("Make sure opensearch.yml on all nodes contains:");
                System.out.println("plugins.security.authcz.admin_dn:"+System.lineSeparator()+
                        "  - \"" + whoAmIResNode.get("dn") + "\"");
            } else {
                System.out.println("Seems you use a node certificate. This is not permitted, you have to use a client certificate and register it as admin_dn in opensearch.yml");
            }
            return false;
        } else if (whoAmIResNode.get("is_node_certificate_request").asBoolean()) {
            System.out.println("ERR: Seems you use a node certificate which is also an admin certificate");
            System.out.println("     That may have worked with older OpenSearch Security versions but it indicates");
            System.out.println("     a configuration error and is therefore forbidden now.");
            return false;
        }
        return true;
    }

    private static void setPasswordSingleUser(String user, RestClient restClient, String password) throws Exception {
        String body = "[{\"op\": \"add\", \"path\": \"/password\",\"value\": \"" + password + "\"}]";
        StringEntity entity = new StringEntity(body, ContentType.APPLICATION_JSON);
        Request request = new Request("PATCH", "/_plugins/_security/api/internalusers/" + user);
        request.setEntity(entity);
        restClient.performRequest(request);
    }

    private static String createPassword() {
        String upperCaseLetters = RandomStringUtils.random(2, 65, 90, true, true);
        String lowerCaseLetters = RandomStringUtils.random(2, 97, 122, true, true);
        String numbers = RandomStringUtils.randomNumeric(2);
        String specialChars = RandomStringUtils.random(2, 35, 47, false, false);
        String extraChars = RandomStringUtils.random(8, 33, 122, true, true);
        String combinedChars = upperCaseLetters.concat(lowerCaseLetters).concat(numbers).concat(specialChars).concat(extraChars);

        List<Character> passwordAsList = combinedChars.chars().mapToObj(c -> (char) c).collect(Collectors.toList());
        Collections.shuffle(passwordAsList);
        String password = passwordAsList.stream().collect(StringBuilder::new, StringBuilder::append, StringBuilder::append).toString();
        return password;
    }

    private static String promptForPassword(String passwordName, String commandLineOption, String envVarName) throws Exception {
        final Console console = System.console();
        if(console == null) {
            throw new Exception("Cannot allocate a console. Set env var "+envVarName+" or "+commandLineOption+" on commandline in that case");
        }
        return new String(console.readPassword("[%s]", passwordName+" password:"));
    }

    private static SSLContext sslContext(
	        //keystore & truststore related properties
			String ts,
			String tspass,
            String trustStoreType,
            String ks,
            String kspass,
            String keyStoreType,
            String ksAlias,

			//certs related properties
			String cacert,
			String cert,
			String key,
			String keypass) throws Exception {

        final SSLContextBuilder sslContextBuilder = SSLContexts.custom();

		if (ks != null) {
			File keyStoreFile = Paths.get(ks).toFile();

            KeyStore keyStore = KeyStore.getInstance(keyStoreType.toUpperCase());
			keyStore.load(new FileInputStream(keyStoreFile), kspass.toCharArray());
            sslContextBuilder.loadKeyMaterial(keyStore, kspass.toCharArray(), (aliases, socket) -> {
                if (aliases == null || aliases.isEmpty()) {
                    return ksAlias;
                }

                if (ksAlias == null || ksAlias.isEmpty()) {
                    return aliases.keySet().iterator().next();
                }

                return ksAlias;
            });
		}

		if (ts != null) {
			File trustStoreFile = Paths.get(ts).toFile();

			KeyStore trustStore = KeyStore.getInstance(trustStoreType.toUpperCase());
			trustStore.load(new FileInputStream(trustStoreFile), tspass == null ? null : tspass.toCharArray());
            sslContextBuilder.loadTrustMaterial(trustStore, null);
		}

		if (cacert != null) {
			File caCertFile = Paths.get(cacert).toFile();
			try (FileInputStream in = new FileInputStream(caCertFile)) {
				X509Certificate[] certificates = PemKeyReader.loadCertificatesFromStream(in);
				KeyStore trustStore = PemKeyReader.toTruststore("al", certificates);
                sslContextBuilder.loadTrustMaterial(trustStore, null);
			} catch (FileNotFoundException e) {
				throw new IllegalArgumentException("Could not find certificate file " + caCertFile, e);
			} catch (IOException | CertificateException e) {
				throw new IllegalArgumentException("Error while reading certificate file " + caCertFile, e);
			}
		}

        if (cert != null && key != null) {
			File certFile = Paths.get(cert).toFile();
			X509Certificate[] certificates;
			PrivateKey privateKey;
			try (FileInputStream in = new FileInputStream(certFile)) {
				certificates = PemKeyReader.loadCertificatesFromStream(in);
			} catch (FileNotFoundException e) {
				throw new IllegalArgumentException("Could not find certificate file " + certFile, e);
			} catch (IOException | CertificateException e) {
				throw new IllegalArgumentException("Error while reading certificate file " + certFile, e);
			}

			File keyFile = Paths.get(key).toFile();
			try (FileInputStream in = new FileInputStream(keyFile)) {
				privateKey = PemKeyReader.toPrivateKey(in, keypass);
			} catch (FileNotFoundException e) {
				throw new IllegalArgumentException("Could not find certificate key file " + keyFile, e);
			} catch (IOException e) {
				throw new IllegalArgumentException("Error while reading certificate key file " + keyFile, e);
			}

			String alias = "al";
			KeyStore keyStore = PemKeyReader.toKeystore(alias, "changeit".toCharArray(), certificates, privateKey);
            sslContextBuilder.loadKeyMaterial(keyStore, "changeit".toCharArray(), (aliases, socket) -> alias);
		}

		return sslContextBuilder.build();
	}

    private static RestHighLevelClient getRestHighLevelClient(SSLContext sslContext,
															  boolean nhnv,
															  String[] enabledProtocols,
															  String[] enabledCiphers,
															  String hostname,
															  int port) {

		final HostnameVerifier hnv = !nhnv ? new DefaultHostnameVerifier() : NoopHostnameVerifier.INSTANCE;

		String[] supportedProtocols = enabledProtocols.length > 0 ? enabledProtocols : null;
		String[] supportedCipherSuites = enabledCiphers.length > 0 ? enabledCiphers : null;

		HttpHost httpHost = new HttpHost(hostname, port, "https");

		RestClientBuilder restClientBuilder = RestClient.builder(httpHost)
				.setHttpClientConfigCallback(
						builder -> builder.setSSLStrategy(
								new SSLIOSessionStrategy(
										sslContext,
										supportedProtocols,
										supportedCipherSuites,
										hnv
								)
						)
				);
		return new RestHighLevelClient(restClientBuilder);
	}

    private static void validate(CommandLine line) throws ParseException {

        if(line.hasOption("ts") && line.hasOption("cacert")) {
            System.out.println("WARN: It makes no sense to specify -ts as well as -cacert");
        }
        
        if(line.hasOption("ks") && line.hasOption("cert")) {
            System.out.println("WARN: It makes no sense to specify -ks as well as -cert");
        }
        
        if(line.hasOption("ks") && line.hasOption("key")) {
            System.out.println("WARN: It makes no sense to specify -ks as well as -key");
        }
        
        if(line.hasOption("cd") && line.hasOption("rl")) {
            System.out.println("WARN: It makes no sense to specify -cd as well as -r");
        }
        
        if(line.hasOption("cd") && line.hasOption("f")) {
            System.out.println("WARN: It makes no sense to specify -cd as well as -f");
        }

        if(line.hasOption("cn") && line.hasOption("icl")) {
            throw new ParseException("Only set one of -cn or -icl");
        }
    }
}
