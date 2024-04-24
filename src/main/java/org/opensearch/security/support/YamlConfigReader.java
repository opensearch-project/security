/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */
package org.opensearch.security.support;

import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.Meta;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;

import static org.opensearch.core.xcontent.DeprecationHandler.THROW_UNSUPPORTED_OPERATION;
import static org.opensearch.security.configuration.ConfigurationRepository.DEFAULT_CONFIG_VERSION;

/**
 * Read YAML security config files
 */
public final class YamlConfigReader {

    private static final Logger LOGGER = LogManager.getLogger(YamlConfigReader.class);

    public static BytesReference yamlContentFor(final CType cType, final Path configDir) throws IOException {
        final var yamlXContent = XContentType.YAML.xContent();
        try (
            final var r = newReader(cType, configDir);
            final var parser = yamlXContent.createParser(NamedXContentRegistry.EMPTY, THROW_UNSUPPORTED_OPERATION, r)
        ) {
            parser.nextToken();
            try (final var xContentBuilder = XContentFactory.jsonBuilder()) {
                xContentBuilder.copyCurrentStructure(parser);
                final var bytesRef = BytesReference.bytes(xContentBuilder);
                validateYamlContent(cType, bytesRef.streamInput());
                return bytesRef;
            }
        }
    }

    public static Reader newReader(final CType cType, final Path configDir) throws IOException {
        final var cTypeFile = cType.configFile(configDir);
        final var fileExists = Files.exists(cTypeFile);
        if (!fileExists && !cType.emptyIfMissing()) {
            throw new IOException("Couldn't find configuration file " + cTypeFile.getFileName());
        }
        if (fileExists) {
            LOGGER.info("Reading {} configuration from {}", cType, cTypeFile.getFileName());
            return new FileReader(cTypeFile.toFile(), StandardCharsets.UTF_8);
        } else {
            LOGGER.info("Reading empty {} configuration", cType);
            return new StringReader(emptyYamlConfigFor(cType));
        }
    }

    private static SecurityDynamicConfiguration<?> emptyConfigFor(final CType cType) {
        final var emptyConfiguration = SecurityDynamicConfiguration.empty();
        emptyConfiguration.setCType(cType);
        emptyConfiguration.set_meta(new Meta());
        emptyConfiguration.get_meta().setConfig_version(DEFAULT_CONFIG_VERSION);
        emptyConfiguration.get_meta().setType(cType.toLCString());
        return emptyConfiguration;
    }

    public static String emptyJsonConfigFor(final CType cType) throws IOException {
        return DefaultObjectMapper.writeValueAsString(emptyConfigFor(cType), false);
    }

    public static String emptyYamlConfigFor(final CType cType) throws IOException {
        return DefaultObjectMapper.YAML_MAPPER.writeValueAsString(emptyConfigFor(cType));
    }

    private static void validateYamlContent(final CType cType, final InputStream in) throws IOException {
        SecurityDynamicConfiguration.fromNode(DefaultObjectMapper.YAML_MAPPER.readTree(in), cType, DEFAULT_CONFIG_VERSION, -1, -1);
    }

}
