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
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.tools;

import java.io.Console;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.io.Writer;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;

import com.google.common.base.Charsets;
import com.google.common.base.Joiner;
import com.google.common.collect.Iterators;
import com.google.common.io.ByteSource;
import com.google.common.io.CharStreams;
import com.google.common.io.Files;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManagerBuilder;
import org.apache.hc.client5.http.nio.AsyncClientConnectionManager;
import org.apache.hc.client5.http.ssl.ClientTlsStrategyBuilder;
import org.apache.hc.client5.http.ssl.DefaultHostnameVerifier;
import org.apache.hc.client5.http.ssl.HostnameVerificationPolicy;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.core5.function.Factory;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.nio.ssl.TlsStrategy;
import org.apache.hc.core5.reactor.ssl.TlsDetails;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.hc.core5.ssl.SSLContexts;

import org.opensearch.ExceptionsHelper;
import org.opensearch.Version;
import org.opensearch.client.json.JsonData;
import org.opensearch.client.json.jackson3.JacksonJsonpMapper;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch._types.HealthStatus;
import org.opensearch.client.opensearch._types.OpenSearchException;
import org.opensearch.client.opensearch._types.Refresh;
import org.opensearch.client.opensearch.cluster.HealthRequest;
import org.opensearch.client.opensearch.cluster.HealthResponse;
import org.opensearch.client.opensearch.cluster.PutClusterSettingsRequest;
import org.opensearch.client.opensearch.core.GetRequest;
import org.opensearch.client.opensearch.core.GetResponse;
import org.opensearch.client.opensearch.core.IndexRequest;
import org.opensearch.client.opensearch.generic.Body;
import org.opensearch.client.opensearch.generic.Requests;
import org.opensearch.client.opensearch.generic.Response;
import org.opensearch.client.opensearch.indices.CreateIndexRequest;
import org.opensearch.client.opensearch.indices.DeleteIndexRequest;
import org.opensearch.client.opensearch.indices.GetFieldMappingRequest;
import org.opensearch.client.opensearch.indices.GetFieldMappingResponse;
import org.opensearch.client.opensearch.indices.IndexSettings;
import org.opensearch.client.opensearch.indices.PutIndicesSettingsRequest;
import org.opensearch.client.opensearch.indices.PutIndicesSettingsResponse;
import org.opensearch.client.transport.httpclient5.ApacheHttpClient5TransportBuilder;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.MediaType;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.NonValidatingObjectMapper;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.ssl.util.ExceptionUtils;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.ConfigHelper;
import org.opensearch.security.support.PemKeyReader;
import org.opensearch.security.support.SecurityJsonNode;
import org.opensearch.transport.client.transport.NoNodeAvailableException;

import tools.jackson.databind.InjectableValues;
import tools.jackson.databind.JsonNode;

import static org.opensearch.core.xcontent.DeprecationHandler.THROW_UNSUPPORTED_OPERATION;
import static org.opensearch.security.support.SecurityUtils.replaceEnvVars;

@SuppressWarnings("deprecation")
public class SecurityAdmin {

    private static final boolean ALLOW_MIXED = Boolean.parseBoolean(System.getenv("OPENDISTRO_SECURITY_ADMIN_ALLOW_MIXED_CLUSTER"));
    private static final String OPENDISTRO_SECURITY_TS_PASS = "OPENDISTRO_SECURITY_TS_PASS";
    private static final String OPENDISTRO_SECURITY_KS_PASS = "OPENDISTRO_SECURITY_KS_PASS";
    private static final String OPENDISTRO_SECURITY_KEYPASS = "OPENDISTRO_SECURITY_KEYPASS";
    // not used in multithreaded fashion, so it's okay to define it as a constant here
    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MMM-dd_HH-mm-ss", Locale.ENGLISH); // NOSONAR
    private static final Map<String, JsonData> ENABLE_ALL_ALLOCATIONS_SETTINGS = Map.of(
        "cluster.routing.allocation.enable",
        JsonData.of("all")
    );

    public static void main(final String[] args) {
        try {
            final int returnCode = execute(args);
            System.exit(returnCode);
        } catch (NoNodeAvailableException e) {
            System.out.println("ERR: Cannot connect to OpenSearch. Please refer to opensearch logfile for more information");
            System.out.println("Trace:");
            System.out.println(ExceptionsHelper.stackTrace(e));
            System.out.println();
            System.exit(-1);
        } catch (IndexNotFoundException e) {
            System.out.println(
                "ERR: No OpenSearch Security configuration index found. Please execute securityadmin with different command line parameters"
            );
            System.out.println("When you run it for the first time do not specify -us, -era, -dra or -rl");
            System.out.println();
            System.exit(-1);
        } catch (Throwable e) {

            if (e instanceof OpenSearchException && e.getMessage() != null && e.getMessage().contains("no permissions")) {

                System.out.println("ERR: You try to connect with a TLS node certificate instead of an admin client certificate");
                System.out.println();
                System.exit(-1);
            }

            System.out.println("ERR: An unexpected " + e.getClass().getSimpleName() + " occurred: " + e.getMessage());
            System.out.println("Trace:");
            System.out.println(ExceptionsHelper.stackTrace(e));
            System.out.println();
            System.exit(-1);
        }
    }

    public static int execute(final String[] args) throws Exception {

        System.out.println("Security Admin v7");
        System.setProperty("security.nowarn.client", "true");
        System.setProperty("jdk.tls.rejectClientInitiatedRenegotiation", "true");

        final HelpFormatter formatter = new HelpFormatter();
        Options options = new Options();
        options.addOption("nhnv", "disable-host-name-verification", false, "Disable hostname verification");
        options.addOption(
            Option.builder("ts").longOpt("truststore").hasArg().argName("file").desc("Path to truststore (JKS/PKCS12 format)").build()
        );
        options.addOption(
            Option.builder("ks").longOpt("keystore").hasArg().argName("file").desc("Path to keystore (JKS/PKCS12 format").build()
        );
        options.addOption(
            Option.builder("tst")
                .longOpt("truststore-type")
                .hasArg()
                .argName("type")
                .desc("JKS or PKCS12, if not given we use the file extension to detect the type")
                .build()
        );
        options.addOption(
            Option.builder("kst")
                .longOpt("keystore-type")
                .hasArg()
                .argName("type")
                .desc("JKS or PKCS12, if not given we use the file extension to detect the type")
                .build()
        );
        options.addOption(
            Option.builder("tspass").longOpt("truststore-password").hasArg().argName("password").desc("Truststore password").build()
        );
        options.addOption(
            Option.builder("kspass").longOpt("keystore-password").hasArg().argName("password").desc("Keystore password").build()
        );
        options.addOption(
            Option.builder("cd").longOpt("configdir").hasArg().argName("directory").desc("Directory for config files").build()
        );
        options.addOption(
            Option.builder("h").longOpt("hostname").hasArg().argName("host").desc("OpenSearch host (default: localhost)").build()
        );
        options.addOption(
            Option.builder("p").longOpt("port").hasArg().argName("port").desc("OpenSearch transport port (default: 9200)").build()
        );
        options.addOption(Option.builder("to").longOpt("timeout").hasArg().argName("timeout").desc("timeout (default: 30s)").build());
        options.addOption(
            Option.builder("cn")
                .longOpt("clustername")
                .hasArg()
                .argName("clustername")
                .desc("Clustername (do not use together with -icl)")
                .build()
        );
        options.addOption("sniff", "enable-sniffing", false, "Enable client.transport.sniff");
        options.addOption("icl", "ignore-clustername", false, "Ignore clustername (do not use together with -cn)");
        options.addOption(Option.builder("r").longOpt("retrieve").desc("retrieve current config").build());
        options.addOption(Option.builder("f").longOpt("file").hasArg().argName("file").desc("file").build());
        options.addOption(Option.builder("t").longOpt("type").hasArg().argName("file-type").desc("file-type").build());
        options.addOption(Option.builder("ksalias").longOpt("keystore-alias").hasArg().argName("alias").desc("Keystore alias").build());
        options.addOption(
            Option.builder("ec")
                .longOpt("enabled-ciphers")
                .hasArg()
                .argName("cipers")
                .desc("Comma separated list of enabled TLS ciphers")
                .build()
        );
        options.addOption(
            Option.builder("ep")
                .longOpt("enabled-protocols")
                .hasArg()
                .argName("protocols")
                .desc("Comma separated list of enabled TLS protocols")
                .build()
        );
        // TODO mark as deprecated and replace it with "era" if "era" is mature enough
        options.addOption(
            Option.builder("us")
                .longOpt("update_settings")
                .hasArg()
                .argName("number of replicas")
                .desc("Update the number of Security index replicas, reload configuration on all nodes and exit")
                .build()
        );
        options.addOption(
            Option.builder("i")
                .longOpt("index")
                .hasArg()
                .argName("indexname")
                .desc("The index OpenSearch Security uses to store the configuration")
                .build()
        );
        options.addOption(Option.builder("era").longOpt("enable-replica-autoexpand").desc("Enable replica auto expand and exit").build());
        options.addOption(Option.builder("dra").longOpt("disable-replica-autoexpand").desc("Disable replica auto expand and exit").build());
        options.addOption(
            Option.builder("rl").longOpt("reload").desc("Reload the configuration on all nodes, flush all Security caches and exit").build()
        );
        options.addOption(Option.builder("ff").longOpt("fail-fast").desc("fail-fast if something goes wrong").build());
        options.addOption(Option.builder("dg").longOpt("diagnose").desc("Log diagnostic trace into a file").build());
        options.addOption(
            Option.builder("dci").longOpt("delete-config-index").desc("Delete '.opendistro_security' config index and exit.").build()
        );
        options.addOption(Option.builder("esa").longOpt("enable-shard-allocation").desc("Enable all shard allocation and exit.").build());
        options.addOption(
            Option.builder("arc")
                .longOpt("accept-red-cluster")
                .desc("Also operate on a red cluster. If not specified the cluster state has to be at least yellow.")
                .build()
        );

        options.addOption(Option.builder("cacert").hasArg().argName("file").desc("Path to trusted cacert (PEM format)").build());
        options.addOption(Option.builder("cert").hasArg().argName("file").desc("Path to admin certificate in PEM format").build());
        options.addOption(Option.builder("key").hasArg().argName("file").desc("Path to the key of admin certificate").build());
        options.addOption(
            Option.builder("keypass").hasArg().argName("password").desc("Password of the key of admin certificate (optional)").build()
        );

        options.addOption(Option.builder("si").longOpt("show-info").desc("Show system and license info").build());

        options.addOption(Option.builder("w").longOpt("whoami").desc("Show information about the used admin certificate").build());

        options.addOption(Option.builder("prompt").longOpt("prompt-for-password").desc("Prompt for password if not supplied").build());

        options.addOption(
            Option.builder("er")
                .longOpt("explicit-replicas")
                .hasArg()
                .argName("number of replicas")
                .desc("Set explicit number of replicas or autoexpand expression for .opendistro_security index")
                .build()
        );

        options.addOption(Option.builder("backup").hasArg().argName("folder").desc("Backup configuration to folder").build());

        options.addOption(
            Option.builder("rev")
                .longOpt("resolve-env-vars")
                .desc("Resolve/Substitute env vars in config with their value before uploading")
                .build()
        );

        options.addOption(
            Option.builder("vc")
                .numberOfArgs(1)
                .optionalArg(true)
                .argName("version")
                .longOpt("validate-configs")
                .desc("Validate config for version 6 or 7 (default 7)")
                .build()
        );

        // when adding new options also adjust validate(CommandLine line)

        String hostname = "localhost";
        int port = 9200;
        int timeout = 30;
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
        boolean retrieve = false;
        String ksAlias = null;
        String[] enabledProtocols = new String[0];
        String[] enabledCiphers = new String[0];
        Integer updateSettings = null;
        String index = ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX;
        Boolean replicaAutoExpand = null;
        boolean reload = false;
        boolean failFast = false;
        boolean diagnose = false;
        boolean deleteConfigIndex = false;
        boolean enableShardAllocation = false;
        boolean acceptRedCluster = false;

        String keypass = System.getenv(OPENDISTRO_SECURITY_KEYPASS);
        String cacert = null;
        String cert = null;
        String key = null;
        boolean si;
        boolean whoami;
        final boolean promptForPassword;
        String explicitReplicas = null;
        String backup = null;
        final boolean resolveEnvVars;
        Integer validateConfig = null;

        InjectableValues.Std injectableValues = new InjectableValues.Std();
        injectableValues.addValue(Settings.class, Settings.builder().build());
        DefaultObjectMapper.inject(injectableValues);
        NonValidatingObjectMapper.inject(injectableValues);

        CommandLineParser parser = new DefaultParser();
        try {
            CommandLine line = parser.parse(options, args);

            validate(line);

            hostname = line.getOptionValue("h", hostname);
            port = Integer.parseInt(line.getOptionValue("p", String.valueOf(port)));
            timeout = Integer.parseInt(line.getOptionValue("to", String.valueOf(timeout)));

            promptForPassword = line.hasOption("prompt");

            if (kspass == null || kspass.isEmpty()) {
                kspass = line.getOptionValue("kspass", promptForPassword ? null : "changeit");
            }

            if (tspass == null || tspass.isEmpty()) {
                tspass = line.getOptionValue("tspass", promptForPassword ? null : kspass);
            }

            cd = line.getOptionValue("cd", cd);

            if (!cd.endsWith(File.separator)) {
                cd += File.separator;
            }

            ks = line.getOptionValue("ks", ks);
            ts = line.getOptionValue("ts", ts);
            kst = line.getOptionValue("kst", kst);
            tst = line.getOptionValue("tst", tst);
            nhnv = line.hasOption("nhnv");
            clustername = line.getOptionValue("cn", clustername);
            file = line.getOptionValue("f", file);
            type = line.getOptionValue("t", type);
            retrieve = line.hasOption("r");
            ksAlias = line.getOptionValue("ksalias", ksAlias);
            index = line.getOptionValue("i", index);

            String enabledCiphersString = line.getOptionValue("ec", (String) null);
            String enabledProtocolsString = line.getOptionValue("ep", (String) null);

            if (enabledCiphersString != null) {
                enabledCiphers = enabledCiphersString.split(",");
            }

            if (enabledProtocolsString != null) {
                enabledProtocols = enabledProtocolsString.split(",");
            }

            updateSettings = line.hasOption("us") ? Integer.parseInt(line.getOptionValue("us")) : null;

            reload = line.hasOption("rl");

            if (line.hasOption("era")) {
                replicaAutoExpand = true;
            }

            if (line.hasOption("dra")) {
                replicaAutoExpand = false;
            }

            failFast = line.hasOption("ff");
            diagnose = line.hasOption("dg");
            deleteConfigIndex = line.hasOption("dci");
            enableShardAllocation = line.hasOption("esa");
            acceptRedCluster = line.hasOption("arc");

            cacert = line.getOptionValue("cacert");
            cert = line.getOptionValue("cert");
            key = line.getOptionValue("key");
            keypass = line.getOptionValue("keypass", keypass);

            si = line.hasOption("si");

            whoami = line.hasOption("w");

            explicitReplicas = line.getOptionValue("er", explicitReplicas);

            backup = line.getOptionValue("backup");

            resolveEnvVars = line.hasOption("rev");

            validateConfig = !line.hasOption("vc") ? null : Integer.parseInt(line.getOptionValue("vc", "7"));

            if (validateConfig != null && validateConfig.intValue() != 6 && validateConfig.intValue() != 7) {
                throw new ParseException("version must be 6 or 7");
            }

        } catch (ParseException exp) {
            System.out.println("ERR: Parsing failed.  Reason: " + exp.getMessage());
            formatter.printHelp("securityadmin.sh", options, true);
            return -1;
        }

        if (validateConfig != null) {
            System.out.println("Validate configuration for Version " + validateConfig.intValue());
            return validateConfig(cd, file, type, validateConfig.intValue());
        }

        System.out.print("Will connect to " + hostname + ":" + port);
        Socket socket = new Socket();

        try {

            socket.connect(new InetSocketAddress(hostname, port));

        } catch (java.net.ConnectException ex) {
            System.out.println();
            System.out.println("ERR: Seems there is no OpenSearch running on " + hostname + ":" + port + " - Will exit");
            return (-1);
        } finally {
            try {
                socket.close();
            } catch (Exception e) {
                // ignore
            }
        }

        System.out.println(" ... done");

        if (ks != null) {
            kst = PemKeyReader.extractStoreType(ks, kst);
            if (kspass == null && promptForPassword) {
                kspass = promptForPassword("Keystore", "kspass", OPENDISTRO_SECURITY_KS_PASS);
            }
        }

        if (ts != null) {
            tst = PemKeyReader.extractStoreType(ts, tst);
            if (tspass == null && promptForPassword) {
                tspass = promptForPassword("Truststore", "tspass", OPENDISTRO_SECURITY_TS_PASS);
            }
        }

        if (key != null) {

            if (keypass == null && promptForPassword) {
                keypass = promptForPassword("Pemkey", "keypass", OPENDISTRO_SECURITY_KEYPASS);
            }

        }

        final SSLContext sslContext = sslContext(ts, tspass, tst, ks, kspass, kst, ksAlias, cacert, cert, key, keypass);
        final OpenSearchClient client = getOpenSearchClient(sslContext, nhnv, enabledProtocols, enabledCiphers, hostname, port);
        final String indexName = index;

        try {

            final Response whoAmIRes = client.generic()
                .execute(Requests.create("GET", "/_plugins/_security/whoami", List.of(), Map.of(), null));
            if (whoAmIRes.getStatus() != 200) {
                System.out.println("Unable to check whether cluster is sane because return code was " + whoAmIRes.getStatus());
                return (-1);
            }

            JsonNode whoAmIResNode = DefaultObjectMapper.objectMapper().readTree(whoAmIRes.getBody().map(Body::bodyAsString).orElse(null));
            System.out.println("Connected as " + whoAmIResNode.get("dn"));

            if (!whoAmIResNode.get("is_admin").asBoolean()) {

                System.out.println("ERR: " + whoAmIResNode.get("dn") + " is not an admin user");

                if (!whoAmIResNode.get("is_node_certificate_request").asBoolean()) {
                    System.out.println("Seems you use a client certificate but this one is not registered as admin_dn");
                    System.out.println("Make sure opensearch.yml on all nodes contains:");
                    System.out.println(
                        "plugins.security.authcz.admin_dn:" + System.lineSeparator() + "  - \"" + whoAmIResNode.get("dn") + "\""
                    );
                } else {
                    System.out.println(
                        "Seems you use a node certificate. This is not permitted, you have to use a client certificate and register it as admin_dn in opensearch.yml"
                    );
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
                if (issueWarnings(client) != 0) {
                    return (-1);
                }
            } catch (Exception e1) {
                System.out.println("Unable to check whether cluster is sane");
                throw e1;
            }

            if (updateSettings != null) {
                final int numberOfReplicas = updateSettings;
                IndexSettings indexSettings = IndexSettings.of(s -> s.numberOfReplicas(numberOfReplicas));
                Response res = client.generic()
                    .execute(
                        Requests.create(
                            "PUT",
                            "/_plugins/_security/configupdate",
                            List.of(),
                            Map.of("config_types", Joiner.on(",").join(getTypes())),
                            null
                        )
                    );

                if (res.getStatus() != 200) {
                    System.out.println("Unable to reload configuration because return code was " + res.getStatus());
                    return (-1);
                }

                JsonNode resNode = DefaultObjectMapper.objectMapper().readTree(res.getBody().map(Body::bodyAsString).orElse(null));

                if (resNode.get("configupdate_response").get("has_failures").asBoolean()) {
                    System.out.println("ERR: Unable to reload config due to " + responseToString(res, false) + "/" + resNode);
                }
                final PutIndicesSettingsResponse response = client.indices()
                    .putSettings(PutIndicesSettingsRequest.of(r -> r.index(indexName).settings(indexSettings)));
                System.out.println("Reload config on all nodes");
                System.out.println("Update number of replicas to " + (updateSettings) + " with result: " + response.acknowledged());
                return ((response.acknowledged() && !resNode.get("configupdate_response").get("has_failures").asBoolean()) ? 0 : -1);
            }

            if (reload) {
                Response res = client.generic()
                    .execute(
                        Requests.create(
                            "PUT",
                            "/_plugins/_security/configupdate",
                            List.of(),
                            Map.of("config_types", Joiner.on(",").join(getTypes())),
                            null
                        )
                    );

                if (res.getStatus() != 200) {
                    System.out.println("Unable to reload configuration because return code was " + res.getStatus());
                    return (-1);
                }

                JsonNode resNode = DefaultObjectMapper.objectMapper().readTree(res.getBody().map(Body::bodyAsString).orElse(null));
                if (resNode.get("configupdate_response").get("has_failures").asBoolean()) {
                    System.out.println("ERR: Unable to reload config due to " + responseToString(res, false) + "/" + resNode);
                    return -1;
                }
                System.out.println("Reload config on all nodes");
                return 0;
            }

            if (si) {
                return (0);
            }

            if (whoami) {
                System.out.println(whoAmIResNode.toPrettyString());
                return (0);
            }

            if (replicaAutoExpand != null) {
                final boolean autoExpand = replicaAutoExpand;
                IndexSettings indexSettings = IndexSettings.of(s -> s.autoExpandReplicas(autoExpand ? "0-all" : "false"));
                Response res = client.generic()
                    .execute(
                        Requests.create(
                            "PUT",
                            "/_plugins/_security/configupdate",
                            List.of(),
                            Map.of("config_types", Joiner.on(",").join(getTypes())),
                            null
                        )
                    );

                if (res.getStatus() != 200) {
                    System.out.println("Unable to reload configuration because return code was " + res.getStatus());
                    return (-1);
                }

                JsonNode resNode = DefaultObjectMapper.objectMapper().readTree(res.getBody().map(Body::bodyAsString).orElse(null));

                if (resNode.get("configupdate_response").get("has_failures").asBoolean()) {
                    System.out.println("ERR: Unable to reload config due to " + responseToString(res, false) + "/" + resNode);
                }
                final PutIndicesSettingsResponse response = client.indices()
                    .putSettings(PutIndicesSettingsRequest.of(r -> r.index(indexName).settings(indexSettings)));
                System.out.println("Reload config on all nodes");
                System.out.println("Auto-expand replicas " + (replicaAutoExpand ? "enabled" : "disabled"));
                return ((response.acknowledged() && !resNode.get("configupdate_response").get("has_failures").asBoolean()) ? 0 : -1);
            }

            if (enableShardAllocation) {
                final boolean successful = client.cluster()
                    .putSettings(
                        PutClusterSettingsRequest.of(
                            r -> r.transient_(ENABLE_ALL_ALLOCATIONS_SETTINGS).persistent(ENABLE_ALL_ALLOCATIONS_SETTINGS)
                        )
                    )
                    .acknowledged();

                if (successful) {
                    System.out.println("Persistent and transient shard allocation enabled");
                } else {
                    System.out.println("ERR: Unable to enable shard allocation");
                }

                return (successful ? 0 : -1);
            }

            if (failFast) {
                System.out.println("Fail-fast is activated");
            }

            if (diagnose) {
                generateDiagnoseTrace(client);
            }

            System.out.println(
                "Contacting opensearch cluster '"
                    + clustername
                    + "'"
                    + (acceptRedCluster ? "" : " and wait for YELLOW clusterstate")
                    + " ..."
            );

            HealthResponse chResponse = null;

            while (chResponse == null) {
                try {
                    HealthRequest.Builder chRequest = HealthRequest.builder().timeout(t -> t.time("5m"));
                    if (!acceptRedCluster) {
                        chRequest = chRequest.waitForStatus(HealthStatus.Yellow);
                    }
                    chResponse = client.cluster().health(chRequest.build());
                } catch (Exception e) {

                    Throwable rootCause = ExceptionUtils.getRootCause(e);

                    if (!failFast) {
                        System.out.println(
                            "Cannot retrieve cluster state due to: " + e.getMessage() + ". This is not an error, will keep on trying ..."
                        );
                        System.out.println(
                            "  Root cause: " + rootCause + " (" + e.getClass().getName() + "/" + rootCause.getClass().getName() + ")"
                        );
                        System.out.println(
                            "   * Try running securityadmin.sh with -icl (but no -cn) and -nhnv (If that works you need to check your clustername as well as hostnames in your TLS certificates)"
                        );
                        System.out.println(
                            "   * Make sure that your keystore or PEM certificate is a client certificate (not a node certificate) and configured properly in opensearch.yml"
                        );
                        System.out.println(
                            "   * If this is not working, try running securityadmin.sh with --diagnose and see diagnose trace log file)"
                        );
                        System.out.println("   * Add --accept-red-cluster to allow securityadmin to operate on a red cluster.");

                    } else {
                        System.out.println("ERR: Cannot retrieve cluster state due to: " + e.getMessage() + ".");
                        System.out.println(
                            "  Root cause: " + rootCause + " (" + e.getClass().getName() + "/" + rootCause.getClass().getName() + ")"
                        );
                        System.out.println(
                            "   * Try running securityadmin.sh with -icl (but no -cn) and -nhnv (If that works you need to check your clustername as well as hostnames in your TLS certificates)"
                        );
                        System.out.println(
                            "   * Make also sure that your keystore or PEM certificate is a client certificate (not a node certificate) and configured properly in opensearch.yml"
                        );
                        System.out.println(
                            "   * If this is not working, try running securityadmin.sh with --diagnose and see diagnose trace log file)"
                        );
                        System.out.println("   * Add --accept-red-cluster to allow securityadmin to operate on a red cluster.");

                        return (-1);
                    }

                    Thread.sleep(3000);
                    continue;
                }
            }

            final boolean timedOut = chResponse.timedOut();

            if (!acceptRedCluster && timedOut) {
                System.out.println("ERR: Timed out while waiting for a green or yellow cluster state.");
                System.out.println(
                    "   * Try running securityadmin.sh with -icl (but no -cn) and -nhnv (If that works you need to check your clustername as well as hostnames in your TLS certificates)"
                );
                System.out.println(
                    "   * Make also sure that your keystore or PEM certificate is a client certificate (not a node certificate) and configured properly in opensearch.yml"
                );
                System.out.println(
                    "   * If this is not working, try running securityadmin.sh with --diagnose and see diagnose trace log file)"
                );
                System.out.println("   * Add --accept-red-cluster to allow securityadmin to operate on a red cluster.");
                return (-1);
            }

            System.out.println("Clustername: " + chResponse.clusterName());
            System.out.println("Clusterstate: " + chResponse.status());
            System.out.println("Number of nodes: " + chResponse.numberOfNodes());
            System.out.println("Number of data nodes: " + chResponse.numberOfDataNodes());

            GetFieldMappingResponse securityIndex = null;
            try {
                securityIndex = client.indices().getFieldMapping(GetFieldMappingRequest.of(r -> r.index(indexName).fields("*")));
            } catch (OpenSearchException e1) {
                if (e1.status() == RestStatus.NOT_FOUND.getStatus()) {
                    // ignore
                } else {
                    System.out.println("Unable to get index because return code was " + e1.status());
                    return (-1);
                }
            }
            final boolean indexExists = securityIndex != null;

            int expectedNodeCount = client.cluster().health(HealthRequest.builder().build()).numberOfNodes();

            if (deleteConfigIndex) {
                return deleteConfigIndex(client, index, indexExists);
            }

            if (!indexExists) {
                System.out.print(index + " index does not exists, attempt to create it ... ");
                final int created = createConfigIndex(client, index, explicitReplicas);
                if (created != 0) {
                    return created;
                }

            } else {
                System.out.println(index + " index already exists, so we do not need to create one.");

                try {
                    HealthResponse clusterHealthResponse = client.cluster().health(HealthRequest.of(r -> r.index(indexName)));

                    if (clusterHealthResponse.timedOut()) {
                        System.out.println("ERR: Timed out while waiting for " + index + " index state.");
                    }

                    if (clusterHealthResponse.status() == HealthStatus.Red) {
                        System.out.println("ERR: " + index + " index state is RED.");
                    }

                    if (clusterHealthResponse.status() == HealthStatus.Yellow) {
                        System.out.println("INFO: " + index + " index state is YELLOW, it seems you miss some replicas");
                    }

                } catch (Exception e) {
                    if (!failFast) {
                        System.out.println(
                            "Cannot retrieve "
                                + index
                                + " index state state due to "
                                + e.getMessage()
                                + ". This is not an error, will keep on trying ..."
                        );
                    } else {
                        System.out.println("ERR: Cannot retrieve " + index + " index state state due to " + e.getMessage() + ".");
                        return (-1);
                    }
                }
            }

            if (retrieve) {
                String date = DATE_FORMAT.format(new Date());

                boolean success = retrieveFile(client, cd + "config_" + date + ".yml", index, "config");
                success = retrieveFile(client, cd + "roles_" + date + ".yml", index, "roles") && success;
                success = retrieveFile(client, cd + "roles_mapping_" + date + ".yml", index, "rolesmapping") && success;
                success = retrieveFile(client, cd + "internal_users_" + date + ".yml", index, "internalusers") && success;
                success = retrieveFile(client, cd + "action_groups_" + date + ".yml", index, "actiongroups") && success;
                success = retrieveFile(client, cd + "audit_" + date + ".yml", index, "audit") && success;

                success = retrieveFile(client, cd + "security_tenants_" + date + ".yml", index, "tenants") && success;

                final boolean populateFileIfEmpty = true;
                success = retrieveFile(client, cd + "nodes_dn_" + date + ".yml", index, "nodesdn", populateFileIfEmpty) && success;
                success = retrieveFile(client, cd + "allowlist_" + date + ".yml", index, "allowlist", populateFileIfEmpty) && success;
                return (success ? 0 : -1);
            }

            if (backup != null) {
                return backup(client, index, new File(backup));
            }

            boolean isCdAbs = new File(cd).isAbsolute();

            System.out.println("Populate config from " + (isCdAbs ? cd : new File(".", cd).getCanonicalPath()));

            if (file != null) {
                if (type != null) {
                    System.out.println("Force type: " + type);
                } else {
                    type = readTypeFromFile(new File(file));
                    if (type == null) {
                        System.out.println("ERR: Unable to read type from file");
                        return (-1);
                    }
                }

                if (!CType.lcStringValues().contains(type)) {
                    System.out.println("ERR: Invalid type '" + type + "'");
                    return (-1);
                }

                boolean success = uploadFile(client, file, index, type, resolveEnvVars, timeout);

                if (!success) {
                    System.out.println("ERR: cannot upload configuration, see errors above");
                    return -1;
                }

                Response cur = client.generic()
                    .execute(Requests.create("PUT", "/_plugins/_security/configupdate", List.of(), Map.of("config_types", type), null));
                success = checkConfigUpdateResponse(cur, expectedNodeCount, 1) && success;

                System.out.println("Done with " + (success ? "success" : "failures"));
                return (success ? 0 : -1);
            }

            return upload(client, index, cd, expectedNodeCount, resolveEnvVars, timeout);
        } finally {
            client._transport().close();
        }
    }

    private static boolean checkConfigUpdateResponse(Response response, int expectedNodeCount, int expectedConfigCount) throws IOException {

        if (response.getStatus() != 200) {
            System.out.println("Unable to check configupdate response because return code was " + response.getStatus());
        }

        JsonNode resNode = DefaultObjectMapper.objectMapper().readTree(response.getBody().map(Body::bodyAsString).orElse(null));

        if (resNode.at("/configupdate_response/has_failures").asBoolean()) {
            System.out.println(
                "FAIL: "
                    + resNode.at("/configupdate_response/failures_size").asInt()
                    + " nodes reported failures. Failure is "
                    + responseToString(response, false)
                    + "/"
                    + resNode
            );
        }

        boolean success = resNode.at("/configupdate_response/node_size").asInt() == expectedNodeCount;
        if (!success) {
            System.out.println(
                "FAIL: Expected "
                    + expectedNodeCount
                    + " nodes to return response, but got "
                    + resNode.at("/configupdate_response/node_size").asInt()
            );
        }

        for (JsonNode n : resNode.at("/configupdate_response/nodes")) {
            boolean successNode = (n.get("updated_config_types") != null && n.get("updated_config_size").asInt() == expectedConfigCount);

            if (!successNode) {
                System.out.println(
                    "FAIL: Expected "
                        + expectedConfigCount
                        + " config types for node "
                        + n
                        + " but got "
                        + n.get("updated_config_size").asInt()
                        + " ("
                        + n.get("updated_config_types")
                        + ") due to: "
                        + (n.get("message") == null ? "unknown reason" : n.get("message"))
                );
            } else {
                System.out.println(
                    "SUCC: Expected "
                        + expectedConfigCount
                        + " config types for node "
                        + n
                        + " is "
                        + n.get("updated_config_size").asInt()
                        + " ("
                        + n.get("updated_config_types")
                        + ") due to: "
                        + (n.get("message") == null ? "unknown reason" : n.get("message"))
                );
            }

            success = success && successNode;
        }

        return success && !resNode.at("/configupdate_response/has_failures").asBoolean();
    }

    private static boolean uploadFile(
        final OpenSearchClient client,
        final String filepath,
        final String index,
        final String _id,
        boolean resolveEnvVars,
        int timeout
    ) {
        return uploadFile(client, filepath, index, _id, resolveEnvVars, false, timeout);
    }

    private static boolean uploadFile(
        final OpenSearchClient client,
        final String filepath,
        final String index,
        final String _id,
        boolean resolveEnvVars,
        final boolean populateEmptyIfMissing,
        int timeout
    ) {

        try {
            ConfigHelper.fromYamlFile(filepath, CType.fromString(_id), 2, 0, 0);
        } catch (Exception e) {
            System.out.println("ERR: Seems " + filepath + " is not in OpenSearch Security 7 format: " + e);
            return false;
        }

        System.out.println("Will update '" + "/" + _id + "' with " + filepath);

        try (Reader reader = ConfigHelper.createFileOrStringReader(CType.fromString(_id), 2, filepath, populateEmptyIfMissing)) {
            final String content = CharStreams.toString(reader);
            final BytesReference bytes = readXContent(
                resolveEnvVars ? replaceEnvVars(content, Settings.EMPTY) : content,
                XContentType.YAML
            );
            final String res = client.index(
                IndexRequest.of(
                    r -> r.index(index)
                        .id(_id)
                        .timeout(t -> t.time(timeout + "s"))
                        .refresh(Refresh.True)
                        .document(Map.of(_id, BytesReference.toBytes(bytes)))
                )
            ).id();

            if (_id.equals(res)) {
                System.out.println("   SUCC: Configuration for '" + _id + "' created or updated");
                return true;
            } else {
                System.out.println(
                    "   FAIL: Configuration for '" + _id + "' failed for unknown reasons. Please consult the OpenSearch logfile."
                );
            }
        } catch (Exception e) {
            System.out.println("   FAIL: Configuration for '" + _id + "' failed because of " + e.toString());
        }

        return false;
    }

    private static boolean retrieveFile(final OpenSearchClient client, final String filepath, final String index, final String _id) {
        return retrieveFile(client, filepath, index, _id, false);
    }

    private static boolean retrieveFile(
        final OpenSearchClient client,
        final String filepath,
        final String index,
        final String _id,
        final boolean populateFileIfEmpty
    ) {
        String id = _id;

        System.out.println("Will retrieve '" + "/" + id + "' into " + filepath);
        try (Writer writer = new FileWriter(filepath, StandardCharsets.UTF_8)) {

            final GetResponse<?> response = client.get(GetRequest.of(r -> r.index(index).id(id).refresh(true).realtime(false)), Map.class);

            boolean isEmpty = !response.found() || response.source() == null;
            String yaml;
            if (isEmpty) {
                if (populateFileIfEmpty) {
                    yaml = ConfigHelper.createEmptySdcYaml(CType.fromString(_id), 2);
                } else {
                    System.out.println("   FAIL: Configuration for '" + _id + "' failed because of empty source");
                    return false;
                }
            } else {
                yaml = convertToYaml(_id, (Map<?, ?>) response.source(), true);

                if (null == yaml) {
                    System.out.println("ERR: YML conversion error for " + _id);
                    return false;

                }

                try {
                    ConfigHelper.fromYamlString(yaml, CType.fromString(_id), 2, 0, 0);
                } catch (Exception e) {
                    System.out.println("ERR: Seems " + _id + " from cluster is not in 7 format: " + e);
                    return false;
                }

            }

            writer.write(yaml);
            System.out.println("   SUCC: Configuration for '" + _id + "' stored in " + filepath);
            return true;
        } catch (Exception e) {
            System.out.println("   FAIL: Get configuration for '" + _id + "' failed because of " + e.toString());
        }

        return false;
    }

    private static BytesReference readXContent(final String content, final MediaType mediaType) throws IOException {
        BytesReference retVal;
        XContentParser parser = null;
        try {
            parser = mediaType.xContent().createParser(NamedXContentRegistry.EMPTY, THROW_UNSUPPORTED_OPERATION, content);
            parser.nextToken();
            final XContentBuilder builder = XContentFactory.jsonBuilder();
            builder.copyCurrentStructure(parser);
            retVal = BytesReference.bytes(builder);
        } finally {
            if (parser != null) {
                parser.close();
            }
        }

        // validate
        return retVal;
    }

    @SuppressWarnings("unchecked")
    private static <T> String convertToYaml(String type, Map<?, ?> document, boolean prettyPrint) throws IOException {
        try (XContentBuilder builder = XContentFactory.yamlBuilder()) {
            if (prettyPrint) {
                builder.prettyPrint();
            }
            builder.map((Map<String, ?>) document);
            return builder.toString();
        }
    }

    protected static void generateDiagnoseTrace(final OpenSearchClient client) {

        final String date = DATE_FORMAT.format(new Date());

        final StringBuilder sb = new StringBuilder();
        sb.append("Diagnostic securityadmin trace" + System.lineSeparator());
        sb.append("OpenSearch client version: " + Version.CURRENT + System.lineSeparator());
        sb.append("Client properties: " + System.getProperties() + System.lineSeparator());
        sb.append(date + System.lineSeparator());
        sb.append(System.lineSeparator());

        try {
            sb.append("Who am i:" + System.lineSeparator());
            Response whoAmIRes = client.generic().execute(Requests.create("GET", "/_plugins/_security/whoami", List.of(), Map.of(), null));
            sb.append(responseToString(whoAmIRes, true));
        } catch (Exception e1) {
            sb.append(ExceptionsHelper.stackTrace(e1));
        }

        try {
            sb.append("ClusterHealthRequest:" + System.lineSeparator());
            Response nir = client.generic().execute(Requests.create("GET", "/_cluster/health", List.of(), Map.of(), null));
            sb.append(responseToString(nir, true));
        } catch (Exception e1) {
            sb.append(ExceptionsHelper.stackTrace(e1));
        }

        try {
            sb.append(System.lineSeparator() + "NodesInfoResponse:" + System.lineSeparator());
            Response nir = client.generic().execute(Requests.create("GET", "/_nodes", List.of(), Map.of(), null));
            sb.append(responseToString(nir, true));
        } catch (Exception e1) {
            sb.append(ExceptionsHelper.stackTrace(e1));
        }

        try {
            sb.append(System.lineSeparator() + "NodesStatsRequest:" + System.lineSeparator());
            Response nir = client.generic().execute(Requests.create("GET", "/_nodes/stats", List.of(), Map.of(), null));
            sb.append(responseToString(nir, true));
        } catch (Exception e1) {
            sb.append(ExceptionsHelper.stackTrace(e1));
        }

        try {
            sb.append(System.lineSeparator() + "PendingClusterTasksRequest:" + System.lineSeparator());
            Response nir = client.generic().execute(Requests.create("GET", "/_cluster/pending_tasks", List.of(), Map.of(), null));
            sb.append(responseToString(nir, true));
        } catch (Exception e1) {
            sb.append(ExceptionsHelper.stackTrace(e1));
        }

        try {
            sb.append(System.lineSeparator() + "IndicesStatsRequest:" + System.lineSeparator());
            Response nir = client.generic().execute(Requests.create("GET", "/_stats", List.of(), Map.of(), null));
            sb.append(responseToString(nir, true));
        } catch (Exception e1) {
            sb.append(ExceptionsHelper.stackTrace(e1));
        }

        try {
            File dfile = new File("securityadmin_diag_trace_" + date + ".txt");
            Files.asCharSink(dfile, StandardCharsets.UTF_8).write(sb);
            System.out.println("Diagnostic trace written to: " + dfile.getAbsolutePath());
        } catch (Exception e1) {
            System.out.println("ERR: cannot write diag trace file due to " + e1);
        }
    }

    private static void validate(CommandLine line) throws ParseException {

        if (line.hasOption("ts") && line.hasOption("cacert")) {
            System.out.println("WARN: It makes no sense to specify -ts as well as -cacert");
        }

        if (line.hasOption("ks") && line.hasOption("cert")) {
            System.out.println("WARN: It makes no sense to specify -ks as well as -cert");
        }

        if (line.hasOption("ks") && line.hasOption("key")) {
            System.out.println("WARN: It makes no sense to specify -ks as well as -key");
        }

        if (line.hasOption("cd") && line.hasOption("rl")) {
            System.out.println("WARN: It makes no sense to specify -cd as well as -r");
        }

        if (line.hasOption("cd") && line.hasOption("f")) {
            System.out.println("WARN: It makes no sense to specify -cd as well as -f");
        }

        if (line.hasOption("cn") && line.hasOption("icl")) {
            throw new ParseException("Only set one of -cn or -icl");
        }

        if (line.hasOption("vc") && !line.hasOption("cd") && !line.hasOption("f")) {
            throw new ParseException("Specify at least -cd or -f together with vc");
        }

        if (!line.hasOption("vc") && !line.hasOption("ks") && !line.hasOption("cert") /*&& !line.hasOption("simple-auth")*/) {
            throw new ParseException("Specify at least -ks or -cert");
        }

        if (!line.hasOption("vc") && !line.hasOption("mo") && !line.hasOption("ts") && !line.hasOption("cacert")) {
            throw new ParseException("Specify at least -ts or -cacert");
        }

        // TODO add more validation rules
    }

    private static String promptForPassword(String passwordName, String commandLineOption, String envVarName) throws Exception {
        final Console console = System.console();
        if (console == null) {
            throw new Exception(
                "Cannot allocate a console. Set env var " + envVarName + " or " + commandLineOption + " on commandline in that case"
            );
        }
        return new String(console.readPassword("[%s]", passwordName + " password:"));
    }

    private static int issueWarnings(OpenSearchClient client) throws IOException {
        Response res = client.generic().execute(Requests.create("GET", "/_nodes", List.of(), Map.of(), null));

        if (res.getStatus() != 200) {
            System.out.println("Unable to get nodes " + res.getStatus());
            return -1;
        }

        JsonNode resNode = DefaultObjectMapper.objectMapper().readTree(res.getBody().map(Body::bodyAsString).orElse(null));

        int nodeCount = Iterators.size(resNode.at("/nodes").iterator());

        if (nodeCount > 0) {

            JsonNode[] nodeVersions = Iterators.toArray(resNode.at("/nodes").iterator(), JsonNode.class);

            Version maxVersion = Version.fromString(
                Arrays.stream(nodeVersions)
                    .map(n -> n.at("/version"))
                    .max((n1, n2) -> Version.fromString(n1.asString()).compareTo(Version.fromString(n2.asString())))
                    .get()
                    .asString()
            );
            Version minVersion = Version.fromString(
                Arrays.stream(nodeVersions)
                    .map(n -> n.at("/version"))
                    .min((n1, n2) -> Version.fromString(n1.asString()).compareTo(Version.fromString(n2.asString())))
                    .get()
                    .asString()
            );

            if (!maxVersion.equals(minVersion)) {
                System.out.println(
                    "ERR: Your cluster consists of different node versions. It is not allowed to run securityadmin against a mixed cluster."
                );
                System.out.println("         Minimum node version is " + minVersion.toString());
                System.out.println("         Maximum node version is " + maxVersion.toString());
                if (!ALLOW_MIXED) {
                    return -1;
                }

            } else {
                System.out.println("OpenSearch Version: " + minVersion.toString());
            }

            for (JsonNode n : nodeVersions[0].get("plugins")) {
                if ("org.opensearch.security.OpenSearchSecurityPlugin".equals(n.get("name").asText())) {
                    System.out.println("OpenSearch Security Version: " + n.get("version"));
                    break;
                }
            }
        }

        return 0;
    }

    private static int deleteConfigIndex(OpenSearchClient client, String index, boolean indexExists) throws IOException {
        boolean success = true;

        if (indexExists) {
            success = client.indices().delete(DeleteIndexRequest.of(r -> r.index(index))).acknowledged();
            System.out.print("Deleted index '" + index + "'");
        } else {
            System.out.print("No index '" + index + "' exists, so no need to delete it");
        }

        return (success ? 0 : -1);
    }

    private static int createConfigIndex(OpenSearchClient client, String index, String explicitReplicas) throws IOException {
        IndexSettings.Builder indexSettingsBuilder = IndexSettings.builder().numberOfShards(1);

        if (explicitReplicas != null) {
            if (explicitReplicas.contains("-")) {
                indexSettingsBuilder = indexSettingsBuilder.autoExpandReplicas(explicitReplicas);
            } else {
                indexSettingsBuilder = indexSettingsBuilder.numberOfReplicas(Integer.parseInt(explicitReplicas));
            }
        } else {
            indexSettingsBuilder = indexSettingsBuilder.autoExpandReplicas("0-all");
        }

        final IndexSettings indexSettings = indexSettingsBuilder.build();
        final boolean indexCreated = client.indices()
            .create(CreateIndexRequest.of(r -> r.index(index).settings(indexSettings)))
            .acknowledged();

        if (indexCreated) {
            System.out.println("done (" + (explicitReplicas != null ? explicitReplicas : "0-all") + " replicas)");
            return 0;
        } else {
            System.out.println("failed!");
            System.out.println("FAIL: Unable to create the " + index + " index. See opensearch logs for more details");
            return (-1);
        }
    }

    private static int backup(OpenSearchClient tc, String index, File backupDir) {
        backupDir.mkdirs();

        boolean success = retrieveFile(tc, backupDir.getAbsolutePath() + "/config.yml", index, "config");
        success = retrieveFile(tc, backupDir.getAbsolutePath() + "/roles.yml", index, "roles") && success;

        success = retrieveFile(tc, backupDir.getAbsolutePath() + "/roles_mapping.yml", index, "rolesmapping") && success;
        success = retrieveFile(tc, backupDir.getAbsolutePath() + "/internal_users.yml", index, "internalusers") && success;
        success = retrieveFile(tc, backupDir.getAbsolutePath() + "/action_groups.yml", index, "actiongroups") && success;

        success = retrieveFile(tc, backupDir.getAbsolutePath() + "/tenants.yml", index, "tenants") && success;
        success = retrieveFile(tc, backupDir.getAbsolutePath() + "/nodes_dn.yml", index, "nodesdn", true) && success;
        success = retrieveFile(tc, backupDir.getAbsolutePath() + "/allowlist.yml", index, "allowlist", true) && success;
        success = retrieveFile(tc, backupDir.getAbsolutePath() + "/audit.yml", index, "audit") && success;

        return success ? 0 : -1;
    }

    private static int upload(OpenSearchClient tc, String index, String cd, int expectedNodeCount, boolean resolveEnvVars, int timeout)
        throws IOException {
        boolean success = uploadFile(tc, cd + "config.yml", index, "config", resolveEnvVars, timeout);
        success = uploadFile(tc, cd + "roles.yml", index, "roles", resolveEnvVars, timeout) && success;
        success = uploadFile(tc, cd + "roles_mapping.yml", index, "rolesmapping", resolveEnvVars, timeout) && success;

        success = uploadFile(tc, cd + "internal_users.yml", index, "internalusers", resolveEnvVars, timeout) && success;
        success = uploadFile(tc, cd + "action_groups.yml", index, "actiongroups", resolveEnvVars, timeout) && success;

        success = uploadFile(tc, cd + "tenants.yml", index, "tenants", resolveEnvVars, timeout) && success;

        success = uploadFile(tc, cd + "nodes_dn.yml", index, "nodesdn", resolveEnvVars, true, timeout) && success;
        if (new File(cd + "audit.yml").exists()) {
            success = uploadFile(tc, cd + "audit.yml", index, "audit", resolveEnvVars, timeout) && success;
        }
        if (new File(cd + "allowlist.yml").exists()) {
            success = uploadFile(tc, cd + "allowlist.yml", index, "allowlist", resolveEnvVars, timeout) && success;
        }

        if (!success) {
            System.out.println("ERR: cannot upload configuration, see errors above");
            return -1;
        }

        Response cur = tc.generic()
            .execute(
                Requests.create(
                    "PUT",
                    "/_plugins/_security/configupdate",
                    List.of(),
                    Map.of("config_types", Joiner.on(",").join(getTypes())),
                    null
                )
            );
        success = checkConfigUpdateResponse(cur, expectedNodeCount, getTypes().length) && success;

        System.out.println("Done with " + (success ? "success" : "failures"));
        return (success ? 0 : -1);
    }

    private static String readTypeFromFile(File file) throws IOException {
        if (!file.exists() || !file.isFile()) {
            System.out.println("ERR: No such file " + file.getAbsolutePath());
            return null;
        }
        final JsonNode jsonNode = DefaultObjectMapper.yamlMapper().readTree(file);
        return new SecurityJsonNode(jsonNode).get("_meta").get("type").asString();
    }

    private static int validateConfig(String cd, String file, String type, int version) {
        if (file != null) {
            try {

                if (type == null) {
                    type = readTypeFromFile(new File(file));
                }

                if (type == null) {
                    System.out.println("ERR: Unable to read type from " + file);
                    return -1;
                }

                ConfigHelper.fromYamlFile(file, CType.fromString(type), version == 7 ? 2 : 1, 0, 0);
                return 0;
            } catch (Exception e) {
                System.out.println("ERR: Seems " + file + " is not in " + version + " format: " + e);
                return -1;
            }
        } else if (cd != null) {
            boolean success = validateConfigFile(cd + "action_groups.yml", CType.ACTIONGROUPS, version);
            success = validateConfigFile(cd + "internal_users.yml", CType.INTERNALUSERS, version) && success;
            success = validateConfigFile(cd + "roles.yml", CType.ROLES, version) && success;
            success = validateConfigFile(cd + "roles_mapping.yml", CType.ROLESMAPPING, version) && success;
            success = validateConfigFile(cd + "config.yml", CType.CONFIG, version) && success;

            if (new File(cd + "tenants.yml").exists() && version != 6) {
                success = validateConfigFile(cd + "tenants.yml", CType.TENANTS, version) && success;
            }
            if (new File(cd + "audit.yml").exists()) {
                success = validateConfigFile(cd + "audit.yml", CType.AUDIT, version) && success;
            }

            return success ? 0 : -1;

        }

        return -1;
    }

    private static boolean validateConfigFile(String file, CType<?> cType, int version) {
        try {
            ConfigHelper.fromYamlFile(file, cType, version == 7 ? 2 : 1, 0, 0);
            System.out.println(file + " OK");
            return true;
        } catch (Exception e) {
            System.out.println("ERR: Seems " + file + " is not in " + version + " format: " + e);
            return false;
        }
    }

    private static String[] getTypes() {
        return CType.lcStringValues().toArray(new String[0]);
    }

    private static OpenSearchClient getOpenSearchClient(
        SSLContext sslContext,
        boolean nhnv,
        String[] enabledProtocols,
        String[] enabledCiphers,
        String hostname,
        int port
    ) {

        final HostnameVerifier hnv = !nhnv ? new DefaultHostnameVerifier() : NoopHostnameVerifier.INSTANCE;

        String[] supportedProtocols = enabledProtocols.length > 0 ? enabledProtocols : null;
        String[] supportedCipherSuites = enabledCiphers.length > 0 ? enabledCiphers : null;

        HttpHost httpHost = new HttpHost("https", hostname, port);

        ApacheHttpClient5TransportBuilder clientBuilder = ApacheHttpClient5TransportBuilder.builder(httpHost)
            .setHttpClientConfigCallback(builder -> {
                TlsStrategy tlsStrategy = ClientTlsStrategyBuilder.create()
                    .setSslContext(sslContext)
                    .setTlsVersions(supportedProtocols)
                    .setCiphers(supportedCipherSuites)
                    .setHostVerificationPolicy(HostnameVerificationPolicy.CLIENT)
                    .setHostnameVerifier(hnv)
                    // See please https://issues.apache.org/jira/browse/HTTPCLIENT-2219
                    .setTlsDetailsFactory(new Factory<SSLEngine, TlsDetails>() {
                        @Override
                        public TlsDetails create(final SSLEngine sslEngine) {
                            return new TlsDetails(sslEngine.getSession(), sslEngine.getApplicationProtocol());
                        }
                    })
                    .build();

                final AsyncClientConnectionManager cm = PoolingAsyncClientConnectionManagerBuilder.create()
                    .setTlsStrategy(tlsStrategy)
                    .build();

                builder.setConnectionManager(cm);
                return builder;
            });
        return new OpenSearchClient(clientBuilder.setMapper(new JacksonJsonpMapper()).build());
    }

    private static SSLContext sslContext(
        // keystore & trusstore related properties
        String ts,
        String tspass,
        String trustStoreType,
        String ks,
        String kspass,
        String keyStoreType,
        String ksAlias,

        // certs related properties
        String cacert,
        String cert,
        String key,
        String keypass
    ) throws Exception {

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

    private static String responseToString(Response response, boolean prettyJson) {
        ByteSource byteSource = new ByteSource() {
            @Override
            public InputStream openStream() throws IOException {
                return response.getBody().map(Body::body).orElse(InputStream.nullInputStream());
            }
        };

        try {
            String value = byteSource.asCharSource(Charsets.UTF_8).read();

            if (prettyJson) {
                return DefaultObjectMapper.objectMapper().readTree(value).toPrettyString();
            }

            return value;
        } catch (Exception e) {
            return "ERR: Unable to handle response due to " + e;
        }
    }
}
