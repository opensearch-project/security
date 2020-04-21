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
 * Portions Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package com.amazon.opendistroforelasticsearch.security.support;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;

import com.amazon.opendistroforelasticsearch.security.securityconf.impl.Meta;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.support.WriteRequest.RefreshPolicy;
import org.elasticsearch.client.Client;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.XContentType;

import com.amazon.opendistroforelasticsearch.security.DefaultObjectMapper;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.CType;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.SecurityDynamicConfiguration;

public class ConfigHelper {
    
    private static final Logger LOGGER = LogManager.getLogger(ConfigHelper.class);

    public static void uploadFile(Client tc, String filepath, String index, CType cType, int configVersion) throws Exception {
        uploadFile(tc, filepath, index, cType, configVersion, false);
    }

    public static void uploadFile(Client tc, String filepath, String index, CType cType, int configVersion, boolean populateEmptyIfFileMissing) throws Exception {
        LOGGER.info("Will update '" + cType + "' with " + filepath + " and populate it with empty doc if file missing and populateEmptyIfFileMissing=" + populateEmptyIfFileMissing);

        if (!populateEmptyIfFileMissing) {
            ConfigHelper.fromYamlFile(filepath, cType, configVersion, 0, 0);
        }
        
        try (Reader reader = createFileOrStringReader(cType, configVersion, filepath, populateEmptyIfFileMissing)) {

            final String res = tc
                    .index(new IndexRequest(index).type(configVersion==1?"security":"_doc").id(cType.toLCString()).setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                            .source(cType.toLCString(), readXContent(reader, XContentType.YAML))).actionGet().getId();

            if (!cType.toLCString().equals(res)) {
                throw new Exception("   FAIL: Configuration for '" + cType.toLCString()
                        + "' failed for unknown reasons. Pls. consult logfile of elasticsearch");
            }
        }
    }

    public static Reader createFileOrStringReader(CType cType, int configVersion, String filepath, boolean populateEmptyIfFileMissing) throws Exception {
        Reader reader;
        if (!populateEmptyIfFileMissing || new File(filepath).exists()) {
            reader = new FileReader(filepath);
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

    public static BytesReference readXContent(final Reader reader, final XContentType xContentType) throws IOException {
        BytesReference retVal;
        XContentParser parser = null;
        try {
            parser = XContentFactory.xContent(xContentType).createParser(NamedXContentRegistry.EMPTY, OpenDistroSecurityDeprecationHandler.INSTANCE, reader);
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

    public static <T> SecurityDynamicConfiguration<T> fromYamlReader(Reader yamlReader, CType ctype, int version, long seqNo, long primaryTerm) throws IOException {
        try {
            return SecurityDynamicConfiguration.fromNode(DefaultObjectMapper.YAML_MAPPER.readTree(yamlReader), ctype, version, seqNo, primaryTerm);
        } finally {
            if(yamlReader != null) {
                yamlReader.close();
            }
        }
    }

    public static <T> SecurityDynamicConfiguration<T> fromYamlFile(String filepath, CType ctype, int version, long seqNo, long primaryTerm) throws IOException {
        return fromYamlReader(new FileReader(filepath), ctype, version, seqNo, primaryTerm);
    }

    public static <T> SecurityDynamicConfiguration<T> fromYamlString(String yamlString, CType ctype, int version, long seqNo, long primaryTerm) throws IOException {
        return fromYamlReader(new StringReader(yamlString), ctype, version, seqNo, primaryTerm);
    }

}
