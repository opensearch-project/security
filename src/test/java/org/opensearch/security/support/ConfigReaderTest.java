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

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;

import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.securityconf.impl.CType;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.opensearch.security.configuration.ConfigurationRepository.DEFAULT_CONFIG_VERSION;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class ConfigReaderTest {

    @ClassRule
    public static TemporaryFolder folder = new TemporaryFolder();

    private static File configDir;

    @BeforeClass
    public static void createConfigFile() throws IOException {
        configDir = folder.newFolder("config");
    }

    @Test
    public void testThrowsIOExceptionForMandatoryCTypes() {
        for (final var cType : CType.requiredConfigTypes()) {
            assertThrows(IOException.class, () -> YamlConfigReader.newReader(cType, configDir.toPath()));
        }
    }

    @Test
    public void testCreateReaderForNonMandatoryCTypes() throws IOException {
        final var yamlMapper = DefaultObjectMapper.YAML_MAPPER;
        for (final var cType : CType.notRequiredConfigTypes()) {
            try (final var reader = new BufferedReader(YamlConfigReader.newReader(cType, configDir.toPath()))) {
                final var emptyYaml = yamlMapper.readTree(reader);
                assertTrue(emptyYaml.has("_meta"));

                final var meta = emptyYaml.get("_meta");
                assertThat(meta.get("type").asText(), is(cType.toLCString()));
                assertThat(meta.get("config_version").asInt(), is(DEFAULT_CONFIG_VERSION));
            }
        }
    }

}
