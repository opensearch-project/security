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

package org.opensearch.security.support;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.AccessController;
import java.security.PrivilegedExceptionAction;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.DocWriteRequest.OpType;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.Client;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.xcontent.MediaType;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.engine.VersionConflictEngineException;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.Meta;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;

import static org.opensearch.core.xcontent.DeprecationHandler.THROW_UNSUPPORTED_OPERATION;

@Deprecated
public class ConfigHelper {

    private static final Logger LOGGER = LogManager.getLogger(ConfigHelper.class);

    public static void uploadFile(Client tc, String filepath, String index, CType cType, int configVersion) throws Exception {
        uploadFile(tc, filepath, index, cType, configVersion, false);
    }

    public static void uploadFile(
        Client tc,
        String filepath,
        String index,
        CType cType,
        int configVersion,
        boolean populateEmptyIfFileMissing
    ) throws Exception {
        final String configType = cType.toLCString();
        LOGGER.info(
            "Will update '"
                + configType
                + "' with "
                + filepath
                + " and populate it with empty doc if file missing and populateEmptyIfFileMissing="
                + populateEmptyIfFileMissing
        );

        AccessController.doPrivileged((PrivilegedExceptionAction<Void>) () -> {
            if (!populateEmptyIfFileMissing) {
                ConfigHelper.fromYamlFile(filepath, cType, configVersion, 0, 0);
            }

            try (Reader reader = createFileOrStringReader(cType, configVersion, filepath, populateEmptyIfFileMissing)) {

                final IndexRequest indexRequest = new IndexRequest(index).id(configType)
                    .opType(OpType.CREATE)
                    .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                    .source(configType, readXContent(reader, XContentType.YAML));
                final String res = tc.index(indexRequest).actionGet().getId();

                if (!configType.equals(res)) {
                    throw new Exception(
                        "   FAIL: Configuration for '" + configType + "' failed for unknown reasons. Pls. consult logfile of opensearch"
                    );
                }
                LOGGER.info("Doc with id '{}' and version {} is updated in {} index.", configType, configVersion, index);
            } catch (VersionConflictEngineException versionConflictEngineException) {
                LOGGER.info("Index {} already contains doc with id {}, skipping update.", index, configType);
            }
            return null;
        });
    }

    public static Reader createFileOrStringReader(CType cType, int configVersion, String filepath, boolean populateEmptyIfFileMissing)
        throws Exception {
        Reader reader;
        if (!populateEmptyIfFileMissing || new File(filepath).exists()) {
            reader = new FileReader(filepath, StandardCharsets.UTF_8);
        } else {
            reader = new StringReader(createEmptySdcYaml(cType, configVersion));
        }
        return reader;
    }

    public static SecurityDynamicConfiguration<?> createEmptySdc(CType cType, int configVersion) throws Exception {
        SecurityDynamicConfiguration<?> empty = SecurityDynamicConfiguration.empty();
        if (configVersion == 2) {
            empty.setCType(cType);
            empty.set_meta(new Meta());
            empty.get_meta().setConfig_version(configVersion);
            empty.get_meta().setType(cType.toLCString());
        }
        String string = DefaultObjectMapper.writeValueAsString(empty, false);
        SecurityDynamicConfiguration<?> c = SecurityDynamicConfiguration.fromJson(string, cType, configVersion, -1, -1);
        return c;
    }

    public static String createEmptySdcYaml(CType cType, int configVersion) throws Exception {
        return DefaultObjectMapper.YAML_MAPPER.writeValueAsString(createEmptySdc(cType, configVersion));
    }

    public static BytesReference readXContent(final Reader reader, final MediaType mediaType) throws IOException {
        BytesReference retVal;
        XContentParser parser = null;
        try {
            parser = mediaType.xContent().createParser(NamedXContentRegistry.EMPTY, THROW_UNSUPPORTED_OPERATION, reader);
            parser.nextToken();
            final XContentBuilder builder = XContentFactory.jsonBuilder();
            builder.copyCurrentStructure(parser);
            retVal = BytesReference.bytes(builder);
        } finally {
            if (parser != null) {
                parser.close();
            }
        }
        return retVal;
    }

    public static <T> SecurityDynamicConfiguration<T> fromYamlReader(
        Reader yamlReader,
        CType ctype,
        int version,
        long seqNo,
        long primaryTerm
    ) throws IOException {
        try {
            return SecurityDynamicConfiguration.fromNode(
                DefaultObjectMapper.YAML_MAPPER.readTree(yamlReader),
                ctype,
                version,
                seqNo,
                primaryTerm
            );
        } finally {
            if (yamlReader != null) {
                yamlReader.close();
            }
        }
    }

    public static <T> SecurityDynamicConfiguration<T> fromYamlFile(String filepath, CType ctype, int version, long seqNo, long primaryTerm)
        throws IOException {
        return fromYamlReader(new FileReader(filepath, StandardCharsets.UTF_8), ctype, version, seqNo, primaryTerm);
    }

    public static <T> SecurityDynamicConfiguration<T> fromYamlString(
        String yamlString,
        CType ctype,
        int version,
        long seqNo,
        long primaryTerm
    ) throws IOException {
        return fromYamlReader(new StringReader(yamlString), ctype, version, seqNo, primaryTerm);
    }

}
