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

import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.auditlog.config.AuditConfig;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(name = "audit_config_migrater.sh", mixinStandardHelpOptions = true, description = "Migrates audit configuration from opensearch.yml to audit.yml format.",
    header = {
        "",
        "@|cyan    ___                   ____                      _  |@",
        "@|cyan   / _ \\ _ __   ___ _ __ / ___|  ___  __ _ _ __ ___| |__ |@",
        "@|cyan  | | | | '_ \\ / _ \\ '_ \\\\___ \\ / _ \\/ _` | '__/ __| '_ \\|@",
        "@|cyan  | |_| | |_) |  __/ | | |___) |  __/ (_| | | | (__| | | ||@",
        "@|cyan   \\___/| .__/ \\___|_| |_|____/ \\___|\\__,_|_|  \\___|_| |_||@",
        "@|cyan        |_||@                @|bold,yellow Security Tools|@",
        ""
    })
public class AuditConfigMigrater implements Runnable {

    private static final String AUDIT_YML = "audit.yml";
    private static final String OPENSEARCH_YML = "opensearch.yml";
    private static final String OPENSEARCH_AUDIT_FILTERED_YML = "opensearch.audit-filtered.yml";
    private static final String OPENSEARCH_PATH_CONF_ENV = "OPENSEARCH_PATH_CONF";

    @Option(names = "-s", paramLabel = "<source>", description = "Path to opensearch.yml file to migrate. If not specified, will try to lookup env OPENSEARCH_PATH_CONF followed by lookup in current directory.")
    private String source;

    @Option(names = "-oad", paramLabel = "<output-audit-dir>", description = "Output directory to store the generated audit.yml file.")
    private String outputAuditDir;

    @Option(names = "-oed", paramLabel = "<output-opensearch-dir>", description = "Output directory to store the generated opensearch.audit-filtered.yml file.")
    private String outputOpensearchDir;

    public static void main(String[] args) {
        int exitCode = new CommandLine(new AuditConfigMigrater()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public void run() {
        try {
            // find source path. if not specified, use environment followed by current directory path
            final String opensearchPathConfDirEnv = System.getenv(OPENSEARCH_PATH_CONF_ENV);
            final String opensearchPath = sanitizeFilePath(
                opensearchPathConfDirEnv != null ? opensearchPathConfDirEnv : ".",
                OPENSEARCH_YML
            );
            final String sourcePath = source != null ? source : opensearchPath;

            // audit output directory
            final String auditOutput = sanitizeFilePath(outputAuditDir != null ? outputAuditDir : ".", AUDIT_YML);
            // opensearch output directory
            final String opensearchOutput = sanitizeFilePath(outputOpensearchDir != null ? outputOpensearchDir : ".", OPENSEARCH_AUDIT_FILTERED_YML);

            // create settings builder
            System.out.println("Using source opensearch.yml file from path " + sourcePath);
            final Settings.Builder settingsBuilder = Settings.builder().loadFromPath(Paths.get(sourcePath));

            // create audit config
            final Map<String, Object> result = ImmutableMap.of(
                "_meta",
                ImmutableMap.of("type", "audit", "config_version", 2),
                "config",
                AuditConfig.from(settingsBuilder.build())
            );

            // write audit.yml.example
            DefaultObjectMapper.yamlMapper().writeValue(new File(auditOutput), result);

            // remove all deprecated values opensearch.yml
            System.out.println("Looking for deprecated keys in " + sourcePath);
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
            System.err.println("Error: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

    private static String sanitizeFilePath(String path, final String file) {
        if (!path.endsWith(File.separator)) {
            path += File.separator;
        }
        return path + file;
    }
}
