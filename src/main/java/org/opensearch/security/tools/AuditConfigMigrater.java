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

import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.Map;

import com.google.common.collect.ImmutableMap;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.auditlog.config.AuditConfig;

public class AuditConfigMigrater {

    private static final String AUDIT_YML = "audit.yml";
    private static final String OPENSEARCH_YML = "opensearch.yml";
    private static final String OPENSEARCH_AUDIT_FILTERED_YML = "opensearch.audit-filtered.yml";
    private static final String OPENSEARCH_PATH_CONF_ENV = "OPENSEARCH_PATH_CONF";

    private static final Options options = new Options();
    private static final HelpFormatter formatter = new HelpFormatter();
    private static final CommandLineParser parser = new DefaultParser();

    public static void main(String[] args) {
        options.addOption(
            Option.builder("s")
                .argName("source")
                .hasArg()
                .desc(
                    "Path to opensearch.yml file to migrate. If not specified, will try to lookup env "
                        + OPENSEARCH_PATH_CONF_ENV
                        + " followed by lookup in current directory."
                )
                .build()
        );
        options.addOption(
            Option.builder("oad")
                .argName("output-audit-dir")
                .hasArg()
                .desc(
                    "Output directory to store the generated "
                        + AUDIT_YML
                        + " file. To be uploaded in the index, the file must be present in config/opensearch-security/ or use securityadmin tool."
                )
                .build()
        );
        options.addOption(
            Option.builder("oed")
                .argName("output-opensearch-dir")
                .hasArg()
                .desc("Output directory to store the generated " + OPENSEARCH_AUDIT_FILTERED_YML + " file.")
                .build()
        );

        try {
            final CommandLine line = parser.parse(options, args);

            // find source path. if not specified, use environment followed by current directory path
            final String opensearchPathConfDirEnv = System.getenv(OPENSEARCH_PATH_CONF_ENV);
            final String opensearchPath = sanitizeFilePath(
                opensearchPathConfDirEnv != null ? opensearchPathConfDirEnv : ".",
                OPENSEARCH_YML
            );
            final String source = line.getOptionValue("s", opensearchPath);

            // audit output directory
            final String auditOutput = sanitizeFilePath(line.getOptionValue("oad", "."), AUDIT_YML);
            // opensearch output directory
            final String opensearchOutput = sanitizeFilePath(line.getOptionValue("oed", "."), OPENSEARCH_AUDIT_FILTERED_YML);

            // create settings builder
            System.out.println("Using source opensearch.yml file from path " + source);
            final Settings.Builder settingsBuilder = Settings.builder().loadFromPath(Paths.get(source));

            // create audit config
            final Map<String, Object> result = ImmutableMap.of(
                "_meta",
                ImmutableMap.of("type", "audit", "config_version", 2),
                "config",
                AuditConfig.from(settingsBuilder.build())
            );

            // write audit.yml.example
            DefaultObjectMapper.YAML_MAPPER.writeValue(new File(auditOutput), result);

            // remove all deprecated values opensearch.yml
            System.out.println("Looking for deprecated keys in " + source);
            AuditConfig.DEPRECATED_KEYS.forEach(key -> {
                if (settingsBuilder.get(key) != null) {
                    System.out.println(" " + key);
                }
                settingsBuilder.remove(key);
            });

            // write to opensearch.output.yml
            try (FileOutputStream outputStream = new FileOutputStream(opensearchOutput)) {
                XContentBuilder builder = new XContentBuilder(XContentType.YAML.xContent(), outputStream);
                builder.startObject();
                settingsBuilder.build().toXContent(builder, new ToXContent.MapParams(Collections.singletonMap("flat_settings", "true")));
                builder.endObject();
                builder.close();
            }

            System.out.println("Generated " + AUDIT_YML + " is available at path " + auditOutput);
            System.out.println(
                "Generated "
                    + OPENSEARCH_AUDIT_FILTERED_YML
                    + " is available at path "
                    + opensearchOutput
                    + " Please remove the deprecated keys from your opensearch.yml or replace with the generated file after reviewing."
            );
        } catch (final Exception e) {
            formatter.printHelp("audit_config_migrater.sh", options, true);
            System.exit(-1);
        }
    }

    private static String sanitizeFilePath(String path, final String file) {
        if (!path.endsWith(File.separator)) {
            path += File.separator;
        }
        return path + file;
    }
}
