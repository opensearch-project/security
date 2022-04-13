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

import static org.opensearch.common.xcontent.DeprecationHandler.THROW_UNSUPPORTED_OPERATION;
import static org.opensearch.security.support.SecurityUtils.replaceEnvVars;

import java.io.Console;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;

import com.fasterxml.jackson.databind.InjectableValues;
import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.base.Charsets;
import com.google.common.base.Joiner;
import com.google.common.collect.Iterators;
import com.google.common.io.ByteSource;
import com.google.common.io.CharStreams;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.http.HttpHost;
import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.nio.conn.ssl.SSLIOSessionStrategy;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.admin.cluster.health.ClusterHealthRequest;
import org.opensearch.action.admin.cluster.health.ClusterHealthResponse;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.get.GetIndexRequest;
import org.opensearch.action.admin.indices.get.GetIndexRequest.Feature;
import org.opensearch.action.admin.indices.get.GetIndexResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.Request;
import org.opensearch.client.RequestOptions;
import org.opensearch.client.Response;
import org.opensearch.client.RestClient;
import org.opensearch.client.RestClientBuilder;
import org.opensearch.client.RestHighLevelClient;
import org.opensearch.cluster.health.ClusterHealthStatus;
import org.opensearch.common.bytes.BytesReference;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.rest.RestStatus;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.NonValidatingObjectMapper;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.ssl.util.ExceptionUtils;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.ConfigHelper;
import org.opensearch.security.support.PemKeyReader;

public class PasswordSetup {

    private static final boolean CREATE_AS_LEGACY = Boolean.parseBoolean(System.getenv("OPENDISTRO_SECURITY_ADMIN_CREATE_AS_LEGACY"));
    private static final String OPENDISTRO_SECURITY_TS_PASS = "OPENDISTRO_SECURITY_TS_PASS";
    private static final String OPENDISTRO_SECURITY_KS_PASS = "OPENDISTRO_SECURITY_KS_PASS";
    private static final String OPENDISTRO_SECURITY_KEYPASS = "OPENDISTRO_SECURITY_KEYPASS";
    public static void main(final String[] args) {
        try{
            final int returnCode = execute(args);
            System.exit(returnCode);
        } catch (Throwable e) {
            System.out.println("Unexpected error");
            System.exit(-1);
        }
    }

    public static int execute(final String[] args) throws Exception {

        System.setProperty("security.nowarn.client","true");
        System.setProperty("jdk.tls.rejectClientInitiatedRenegotiation","true");

        final HelpFormatter formatter = new HelpFormatter();
        Options options = new Options();
        options.addOption( "nhnv", "disable-host-name-verification", false, "Disable hostname verification" );
        options.addOption(Option.builder("ts").longOpt("truststore").hasArg().argName("file").desc("Path to truststore (JKS/PKCS12 format)").build());
        options.addOption(Option.builder("ks").longOpt("keystore").hasArg().argName("file").desc("Path to keystore (JKS/PKCS12 format").build());
        options.addOption(Option.builder("tst").longOpt("truststore-type").hasArg().argName("type").desc("JKS or PKCS12, if not given we use the file extension to dectect the type").build());
        options.addOption(Option.builder("kst").longOpt("keystore-type").hasArg().argName("type").desc("JKS or PKCS12, if not given we use the file extension to dectect the type").build());
        options.addOption(Option.builder("tspass").longOpt("truststore-password").hasArg().argName("password").desc("Truststore password").build());
        options.addOption(Option.builder("kspass").longOpt("keystore-password").hasArg().argName("password").desc("Keystore password").build());
        options.addOption(Option.builder("cd").longOpt("configdir").hasArg().argName("directory").desc("Directory for config files").build());
        options.addOption(Option.builder("h").longOpt("hostname").hasArg().argName("host").desc("OpenSearch host (default: localhost)").build());
        options.addOption(Option.builder("p").longOpt("port").hasArg().argName("port").desc("OpenSearch transport port (default: 9200)").build());
        options.addOption(Option.builder("cn").longOpt("clustername").hasArg().argName("clustername").desc("Clustername (do not use together with -icl)").build());
        options.addOption( "icl", "ignore-clustername", false, "Ignore clustername (do not use together with -cn)" );
        options.addOption(Option.builder("ksalias").longOpt("keystore-alias").hasArg().argName("alias").desc("Keystore alias").build());
        options.addOption(Option.builder("ff").longOpt("fail-fast").desc("fail-fast if something goes wrong").build());
        options.addOption(Option.builder("arc").longOpt("accept-red-cluster").desc("Also operate on a red cluster. If not specified the cluster state has to be at least yellow.").build());

        options.addOption(Option.builder("cacert").hasArg().argName("file").desc("Path to trusted cacert (PEM format)").build());
        options.addOption(Option.builder("cert").hasArg().argName("file").desc("Path to admin certificate in PEM format").build());
        options.addOption(Option.builder("key").hasArg().argName("file").desc("Path to the key of admin certificate").build());
        options.addOption(Option.builder("keypass").hasArg().argName("password").desc("Password of the key of admin certificate (optional)").build());

        options.addOption(Option.builder("si").longOpt("show-info").desc("Show system and license info").build());
        
        String hostname = "localhost";
        int port = 9200;
        String kspass = System.getenv(OPENDISTRO_SECURITY_KS_PASS);
        String tspass = System.getenv(OPENDISTRO_SECURITY_TS_PASS);
        String cd = ".";
        String ks = null;
        String ts = null;
        String kst = null;
        String tst = null;
        boolean nhnv = false;

        String clustername = "opensearch";
        String file = null;
        String type = null;
        String ksAlias = null;
        String[] enabledProtocols = new String[0];
        String[] enabledCiphers = new String[0];
        String index = ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX;
        boolean failFast = false;
        boolean acceptRedCluster = false;
        
        String keypass = System.getenv(OPENDISTRO_SECURITY_KEYPASS);
        String cacert = null;
        String cert = null;
        String key = null;
        boolean si;
        boolean whoami;
        final boolean promptForPassword;
        String explicitReplicas = null;
        Integer validateConfig = null;
        String migrateOffline = null;
        final boolean resolveEnvVars;

        InjectableValues.Std injectableValues = new InjectableValues.Std();
        injectableValues.addValue(Settings.class, Settings.builder().build());
        DefaultObjectMapper.inject(injectableValues);
        NonValidatingObjectMapper.inject(injectableValues);

        CommandLineParser parser = new DefaultParser();
        try {
            CommandLine line = parser.parse( options, args );
            
            validate(line);
            
            hostname = line.getOptionValue("h", hostname);
            port = Integer.parseInt(line.getOptionValue("p", String.valueOf(port)));

            promptForPassword = line.hasOption("prompt");
            
            if(kspass == null || kspass.isEmpty()) {
                kspass = line.getOptionValue("kspass",promptForPassword?null:"changeit");
            }
            
            if(tspass == null || tspass.isEmpty()) {
                tspass = line.getOptionValue("tspass",promptForPassword?null:kspass);
            }

            cd = line.getOptionValue("cd", cd);
            
            if(!cd.endsWith(File.separator)) {
                cd += File.separator;
            }
            
            ks = line.getOptionValue("ks",ks);
            ts = line.getOptionValue("ts",ts);
            kst = line.getOptionValue("kst", kst);
            tst = line.getOptionValue("tst", tst);
            nhnv = line.hasOption("nhnv");
            clustername = line.getOptionValue("cn", clustername);
            file = line.getOptionValue("f", file);
            type = line.getOptionValue("t", type);
            ksAlias = line.getOptionValue("ksalias", ksAlias);
            index = line.getOptionValue("i", index);
            
            String enabledCiphersString = line.getOptionValue("ec", null);
            String enabledProtocolsString = line.getOptionValue("ep", null);
            
            if(enabledCiphersString != null) {
                enabledCiphers = enabledCiphersString.split(",");
            }
            
            if(enabledProtocolsString != null) {
                enabledProtocols = enabledProtocolsString.split(",");
            }
            
            failFast = line.hasOption("ff");
            acceptRedCluster = line.hasOption("arc");
            
            cacert = line.getOptionValue("cacert");
            cert = line.getOptionValue("cert");
            key = line.getOptionValue("key");
            keypass = line.getOptionValue("keypass", keypass);
            si = line.hasOption("si");
            whoami = line.hasOption("w");
            explicitReplicas = line.getOptionValue("er", explicitReplicas);

            validateConfig = !line.hasOption("vc")?null:Integer.parseInt(line.getOptionValue("vc", "7"));
            
            if(validateConfig != null && validateConfig.intValue() != 6 && validateConfig.intValue() != 7) {
                throw new ParseException("version must be 6 or 7");
            }
            
            migrateOffline = line.getOptionValue("mo");

            resolveEnvVars = line.hasOption("rev");
            
        }
        catch( ParseException exp ) {
            System.out.println("ERR: Parsing failed.  Reason: " + exp.getMessage());
            formatter.printHelp("set_passwords.sh", options, true);
            return -1;
        }
        
        if(migrateOffline != null) {
            System.out.println("Migrate "+migrateOffline+" offline");
            final boolean retVal =  Migrater.migrateDirectory(new File(migrateOffline), true);
            return retVal?0:-1;
        }

        System.out.print("Will connect to "+hostname+":"+port);
        Socket socket = new Socket();

        try {
            
            socket.connect(new InetSocketAddress(hostname, port));
            
          } catch (java.net.ConnectException ex) {
            System.out.println();
            System.out.println("ERR: Seems there is no OpenSearch running on "+hostname+":"+port+" - Will exit");
            return (-1);
          } finally {
              try {
                socket.close();
            } catch (Exception e) {
                //ignore
            }
          }
        System.out.println(" ... done");

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

        try (RestHighLevelClient restHighLevelClient = getRestHighLevelClient(sslContext, nhnv, enabledProtocols, enabledCiphers, hostname, port)) {
            RestClient lowLevelClient = restHighLevelClient.getLowLevelClient();
		    Response whoAmIRes = lowLevelClient.performRequest(new Request("GET", "/_plugins/_security/whoami"));
			if (whoAmIRes.getStatusLine().getStatusCode() != 200) {
				System.out.println("Unable to check whether cluster is sane because return code was " + whoAmIRes.getStatusLine());
				return (-1);
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
                return (-1);
            } else if (whoAmIResNode.get("is_node_certificate_request").asBoolean()) {
                System.out.println("ERR: Seems you use a node certificate which is also an admin certificate");
                System.out.println("     That may have worked with older OpenSearch Security versions but it indicates");
                System.out.println("     a configuration error and is therefore forbidden now.");
                if (failFast) {
                    return (-1);
                }

            }

            try {
                if(issueWarnings(restHighLevelClient) != 0) {
                    return (-1);
                }
            } catch (Exception e1) {
                System.out.println("Unable to check whether cluster is sane");
                throw e1;
            }

            if(si) {
                return (0);
            }

			if (whoami) {
				System.out.println(whoAmIResNode.toPrettyString());
                return (0);
            }

            if(failFast) {
                System.out.println("Fail-fast is activated");
            }

            System.out.println("Contacting opensearch cluster '"+clustername+"'"+(acceptRedCluster?"":" and wait for YELLOW clusterstate")+" ...");

			ClusterHealthResponse chResponse = null;

			while (chResponse == null) {
                try {
					final ClusterHealthRequest chRequest = new ClusterHealthRequest().timeout(TimeValue.timeValueMinutes(5));
					if (!acceptRedCluster) {
						chRequest.waitForYellowStatus();
					}
					chResponse = restHighLevelClient.cluster().health(chRequest, RequestOptions.DEFAULT);
				} catch (Exception e) {

                    Throwable rootCause = ExceptionUtils.getRootCause(e);
                    
                    if(!failFast) {
                        System.out.println("Cannot retrieve cluster state due to: "+e.getMessage()+". This is not an error, will keep on trying ...");
                        System.out.println("  Root cause: "+rootCause+" ("+e.getClass().getName()+"/"+rootCause.getClass().getName()+")");
                        System.out.println("   * Try running set_passwords.sh with -icl (but no -cl) and -nhnv (If that works you need to check your clustername as well as hostnames in your TLS certificates)");   
                        System.out.println("   * Make sure that your keystore or PEM certificate is a client certificate (not a node certificate) and configured properly in opensearch.yml");
                        System.out.println("   * If this is not working, try running set_passwords.sh with --diagnose and see diagnose trace log file)");
                        System.out.println("   * Add --accept-red-cluster to allow set_passwords to operate on a red cluster.");

                    } else {
                        System.out.println("ERR: Cannot retrieve cluster state due to: "+e.getMessage()+".");
                        System.out.println("  Root cause: "+rootCause+" ("+e.getClass().getName()+"/"+rootCause.getClass().getName()+")");
                        System.out.println("   * Try running set_passwords.sh with -icl (but no -cl) and -nhnv (If that works you need to check your clustername as well as hostnames in your TLS certificates)");
                        System.out.println("   * Make also sure that your keystore or PEM certificate is a client certificate (not a node certificate) and configured properly in opensearch.yml");
                        System.out.println("   * If this is not working, try running set_passwords.sh with --diagnose and see diagnose trace log file)"); 
                        System.out.println("   * Add --accept-red-cluster to allow set_passwords to operate on a red cluster.");

                        return (-1);
                    }
                    
                    Thread.sleep(3000);
                    continue;
                }
            }

            final boolean timedOut = chResponse.isTimedOut();

            if (!acceptRedCluster && timedOut) {
                System.out.println("ERR: Timed out while waiting for a green or yellow cluster state.");
                System.out.println("   * Try running set_passwords.sh with -icl (but no -cl) and -nhnv (If that works you need to check your clustername as well as hostnames in your TLS certificates)");
                System.out.println("   * Make also sure that your keystore or PEM certificate is a client certificate (not a node certificate) and configured properly in opensearch.yml");
                System.out.println("   * If this is not working, try running set_passwords.sh with --diagnose and see diagnose trace log file)"); 
                System.out.println("   * Add --accept-red-cluster to allow set_passwords to operate on a red cluster.");
                return (-1);
            }

            System.out.println("Clustername: " + chResponse.getClusterName());
			System.out.println("Clusterstate: " + chResponse.getStatus());
			System.out.println("Number of nodes: " + chResponse.getNumberOfNodes());
			System.out.println("Number of data nodes: " + chResponse.getNumberOfDataNodes());

            GetIndexResponse securityIndex = null;
            try {
				securityIndex = restHighLevelClient.indices().get(new GetIndexRequest().indices(index).addFeatures(Feature.MAPPINGS), RequestOptions.DEFAULT);
			} catch (OpenSearchStatusException e1) {
			    if(e1.status() == RestStatus.NOT_FOUND) {
                //ignore
                } else {
                    System.out.println("Unable to get index because return code was " + e1.status().getStatus());
                    return (-1);
                }
            }
            final boolean indexExists = securityIndex != null;

			int expectedNodeCount = restHighLevelClient.cluster().health(new ClusterHealthRequest(), RequestOptions.DEFAULT).getNumberOfNodes();

               
            if (!indexExists) {
                System.out.print(index +" index does not exists, attempt to create it ... ");
				final int created = createConfigIndex(restHighLevelClient, index, explicitReplicas);
                if(created != 0) {
                    return created;
                }

            } else {
                System.out.println(index+" index already exists, so we do not need to create one.");
                
                try {
					ClusterHealthResponse clusterHealthResponse = restHighLevelClient.cluster().health(new ClusterHealthRequest(index), RequestOptions.DEFAULT);

					if (clusterHealthResponse.isTimedOut()) {
                        System.out.println("ERR: Timed out while waiting for "+index+" index state.");
                    }

					if (clusterHealthResponse.getStatus() == ClusterHealthStatus.RED) {
                        System.out.println("ERR: "+index+" index state is RED.");
                    }

					if (clusterHealthResponse.getStatus() == ClusterHealthStatus.YELLOW) {
                        System.out.println("INFO: "+index+" index state is YELLOW, it seems you miss some replicas");
                    }
                    
                } catch (Exception e) {
                    if(!failFast) {
                        System.out.println("Cannot retrieve "+index+" index state state due to "+e.getMessage()+". This is not an error, will keep on trying ...");
                    } else {
                        System.out.println("ERR: Cannot retrieve "+index+" index state state due to "+e.getMessage()+".");
                        return (-1);
                    }
                }
            }


            final boolean createLegacyMode = !indexExists && CREATE_AS_LEGACY;

            if(createLegacyMode) {
                System.out.println("We forcibly create the new index in legacy mode so that ES 6 config can be uploaded. To move to v7 configs youneed to migrate.");
            }

            final boolean legacy = createLegacyMode || (indexExists
                    && securityIndex.getMappings() != null
                    && securityIndex.getMappings().get(index) != null
                    && securityIndex.getMappings().get(index).containsKey("security"));

            upload(restHighLevelClient, index, cd, legacy, expectedNodeCount, resolveEnvVars);
            Scanner sc = new Scanner(System.in);
            ArrayList<String> users = new ArrayList<String>(Arrays.asList("admin", "kibanaserver", "kibanaro", "logstash", "readall", "snapshotrestore"));
            
            System.out.println("\n\nBeginning Password Setup\n");
            System.out.println("Disclaimer: User must input \\\\ in order to include \\ in a password");

            for (String user: users) {
                    System.out.println("\nEnter password for " + user + ": ");
                    String password = sc.nextLine();
                    setPasswordSingleUser(user, lowLevelClient, password);
            }
            sc.close();
        } catch (Throwable e) {
            System.out.println(e);
            return -1;
        }
        return 0;
    }

    private static void setPasswordSingleUser(String user, RestClient restClient, String password) throws Exception {
        String body = "[{\"op\": \"add\", \"path\": \"/password\",\"value\": \"" + password + "\"}]";
        StringEntity entity = new StringEntity(body, ContentType.APPLICATION_JSON);
        Request request = new Request("PATCH", "/_plugins/_security/api/internalusers/" + user);
        request.setEntity(entity);
        restClient.performRequest(request);
        System.out.println("Done setting password for " + user);
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

    private static int issueWarnings(RestHighLevelClient restHighLevelClient) throws IOException {
		Response res = restHighLevelClient.getLowLevelClient().performRequest(new Request("GET", "/_nodes"));

		if (res.getStatusLine().getStatusCode() != 200) {
			System.out.println("Unable to get nodes " + res.getStatusLine());
			return -1;
		}

		JsonNode resNode = DefaultObjectMapper.objectMapper.readTree(res.getEntity().getContent());

		int nodeCount = Iterators.size(resNode.at("/nodes").iterator());

		if (nodeCount > 0) {

			JsonNode[] nodeVersions = Iterators.toArray(resNode.at("/nodes").iterator(), JsonNode.class);

			for (JsonNode n : nodeVersions[0].get("plugins")) {
				if ("org.opensearch.security.OpenSearchSecurityPlugin".equals(n.get("name").asText())) {
					System.out.println("OpenSearch Security Version: " + n.get("version"));
					break;
                }
			}

		} else {
			System.out.println("ERR: Your cluster consists of zero nodes");
        }

        return 0;
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

        if(line.hasOption("vc") && !line.hasOption("cd") && !line.hasOption("f")) {
            throw new ParseException("Specify at least -cd or -f together with vc");
        }

        if(!line.hasOption("vc") && !line.hasOption("ks") && !line.hasOption("cert") /*&& !line.hasOption("simple-auth")*/) {
            throw new ParseException("Specify at least -ks or -cert");
        }
        
        if(!line.hasOption("vc")  && !line.hasOption("mo") 
                && !line.hasOption("ts") && !line.hasOption("cacert")) {
            throw new ParseException("Specify at least -ts or -cacert");
        }
    }

    private static int createConfigIndex(RestHighLevelClient restHighLevelClient, String index, String explicitReplicas) throws IOException {
        Map<String, Object> indexSettings = new HashMap<>();
        indexSettings.put("index.number_of_shards", 1);
        
        if(explicitReplicas != null) {
            if(explicitReplicas.contains("-")) {
                indexSettings.put("index.auto_expand_replicas", explicitReplicas);
            } else {
                indexSettings.put("index.number_of_replicas", Integer.parseInt(explicitReplicas));
            }
        } else {
            indexSettings.put("index.auto_expand_replicas", "0-all");
        }

		final boolean indexCreated = restHighLevelClient.indices().create(new CreateIndexRequest(index)
						.settings(indexSettings), RequestOptions.DEFAULT)
				.isAcknowledged();

        if (indexCreated) {
            System.out.println("done ("+(explicitReplicas!=null?explicitReplicas:"0-all")+" replicas)");
            return 0;
        } else {
            System.out.println("failed!");
            System.out.println("FAIL: Unable to create the "+index+" index. See opensearch logs for more details");
            return (-1);
        }
    }

    private static boolean uploadFile(final RestHighLevelClient restHighLevelClient, final String filepath, final String index, final String _id, final boolean legacy, boolean resolveEnvVars) {
		return uploadFile(restHighLevelClient, filepath, index, _id, legacy, resolveEnvVars, false);
    }

    private static boolean uploadFile(final RestHighLevelClient restHighLevelClient, final String filepath, final String index, final String _id, final boolean legacy, boolean resolveEnvVars,
        final boolean populateEmptyIfMissing) {

        String type = "_doc";
        String id = _id;
                
        if(legacy) {
            type = "security";
            id = _id;

            try {
                ConfigHelper.fromYamlFile(filepath, CType.fromString(_id), 1, 0, 0);
            } catch (Exception e) {
                System.out.println("ERR: Seems "+filepath+" is not in legacy format: "+e);
                return false;
            }

        } else {
            try {
                ConfigHelper.fromYamlFile(filepath, CType.fromString(_id), 2, 0, 0);
            } catch (Exception e) {
                System.out.println("ERR: Seems "+filepath+" is not in OpenSearch Security 7 format: "+e);
                return false;
            }
        }

        System.out.println("Will update '" + type + "/" + id + "' with " + filepath + " " + (legacy ? "(legacy mode)" : ""));

		try (Reader reader = ConfigHelper.createFileOrStringReader(CType.fromString(_id), legacy ? 1 : 2, filepath, populateEmptyIfMissing)) {
			final String content = CharStreams.toString(reader);
			final String res = restHighLevelClient
					.index(new IndexRequest(index).type(type).id(id).setRefreshPolicy(RefreshPolicy.IMMEDIATE)
							.source(_id, readXContent(resolveEnvVars ? replaceEnvVars(content, Settings.EMPTY) : content, XContentType.YAML)), RequestOptions.DEFAULT).getId();


            if (id.equals(res)) {
                System.out.println("   SUCC: Configuration for '" + _id + "' created or updated");
                return true;
            } else {
                System.out.println("   FAIL: Configuration for '" + _id
                        + "' failed for unknown reasons. Please consult the OpenSearch logfile.");
            }
        } catch (Exception e) {
            System.out.println("   FAIL: Configuration for '" + _id + "' failed because of " + e.toString());
        }

        return false;
    }

    private static BytesReference readXContent(final String content, final XContentType xContentType) throws IOException {
        BytesReference retVal;
        XContentParser parser = null;
        try {
            parser = XContentFactory.xContent(xContentType).createParser(NamedXContentRegistry.EMPTY, THROW_UNSUPPORTED_OPERATION, content);
            parser.nextToken();
            final XContentBuilder builder = XContentFactory.jsonBuilder();
            builder.copyCurrentStructure(parser);
            retVal = BytesReference.bytes(builder);
        } finally {
            if (parser != null) {
                parser.close();
            }
        }
        
        //validate
        return retVal;
    }

    private static String[] getTypes(boolean legacy) {
		if (legacy) {
            
			return new String[]{"config", "roles", "rolesmapping", "internalusers", "actiongroups", "nodesdn", "audit"};
		}
		return CType.lcStringValues().toArray(new String[0]);
	}

    private static int upload(RestHighLevelClient tc, String index, String cd, boolean legacy, int expectedNodeCount, boolean resolveEnvVars) throws IOException {
        boolean success = uploadFile(tc, cd + "config.yml", index, "config", legacy, resolveEnvVars);
        success = uploadFile(tc, cd+"roles.yml", index, "roles", legacy, resolveEnvVars) && success;
        success = uploadFile(tc, cd+"roles_mapping.yml", index, "rolesmapping", legacy, resolveEnvVars) && success;
        
        success = uploadFile(tc, cd+"internal_users.yml", index, "internalusers", legacy, resolveEnvVars) && success;
        success = uploadFile(tc, cd+"action_groups.yml", index, "actiongroups", legacy, resolveEnvVars) && success;

        
        if(!legacy) {
            success = uploadFile(tc, cd+"tenants.yml", index, "tenants", legacy, resolveEnvVars) && success;
        }

        success = uploadFile(tc, cd+"nodes_dn.yml", index, "nodesdn", legacy, resolveEnvVars, true) && success;
        success = uploadFile(tc, cd+"whitelist.yml", index, "whitelist", legacy, resolveEnvVars) && success;
        if (new File(cd+"audit.yml").exists()) {
            success = uploadFile(tc, cd + "audit.yml", index, "audit", legacy, resolveEnvVars) && success;
        }

        if(!success) {
            System.out.println("ERR: cannot upload configuration, see errors above");
            return -1;
        }

		Response cur = tc.getLowLevelClient().performRequest(new Request("PUT", "/_plugins/_security/configupdate?config_types=" + Joiner.on(",").join(getTypes((legacy)))));
		success = checkConfigUpdateResponse(cur, expectedNodeCount, getTypes(legacy).length) && success;

        System.out.println("Done with "+(success?"success":"failures"));

        return (success?0:-1);
    }

    private static boolean checkConfigUpdateResponse(Response response, int expectedNodeCount, int expectedConfigCount) throws IOException {

		if (response.getStatusLine().getStatusCode() != 200) {
			System.out.println("Unable to check configupdate response because return code was " + response.getStatusLine());
		}

		JsonNode resNode = DefaultObjectMapper.objectMapper.readTree(response.getEntity().getContent());

		if (resNode.at("/configupdate_response/has_failures").asBoolean()) {
			System.out.println("FAIL: " + resNode.at("/configupdate_response/failures_size").asInt() + " nodes reported failures. Failure is " + responseToString(response, false) + "/" + resNode);
        }


		boolean success = resNode.at("/configupdate_response/node_size").asInt() == expectedNodeCount;
        if(!success) {
			System.out.println("FAIL: Expected " + expectedNodeCount + " nodes to return response, but got " + resNode.at("/configupdate_response/node_size").asInt());
        }

		for (JsonNode n : resNode.at("/configupdate_response/nodes")) {
			boolean successNode = (n.get("updated_config_types") != null && n.get("updated_config_size").asInt() == expectedConfigCount);

            if(!successNode) {
				System.out.println("FAIL: Expected " + expectedConfigCount + " config types for node " + n + " but got " + n.get("updated_config_size").asInt() + " (" + n.get("updated_config_types") + ") due to: " + (n.get("message") == null ? "unknown reason" : n.get("message")));
			} else {
				System.out.println("SUCC: Expected " + expectedConfigCount + " config types for node " + n + " is " + n.get("updated_config_size").asInt() + " (" + n.get("updated_config_types") + ") due to: " + (n.get("message") == null ? "unknown reason" : n.get("message")));
            }
            
            success = success && successNode;
        }

		return success && !resNode.at("/configupdate_response/has_failures").asBoolean();
    }

    private static String responseToString(Response response, boolean prettyJson) {
		ByteSource byteSource = new ByteSource() {
			@Override
			public InputStream openStream() throws IOException {
				return response.getEntity().getContent();
			}
		};

		try {
			String value = byteSource.asCharSource(Charsets.UTF_8).read();

			if (prettyJson) {
				return DefaultObjectMapper.objectMapper.readTree(value).toPrettyString();
			}

			return value;
		} catch (Exception e) {
			e.printStackTrace();
			return "ERR: Unable to handle response due to " + e;
		}
	}
}
