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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;

import com.google.common.io.Files;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.support.WriteRequest.RefreshPolicy;
import org.elasticsearch.client.Client;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.XContentType;

public class ConfigHelper {
    
    private static final Logger LOGGER = LogManager.getLogger(ConfigHelper.class);

    public static void uploadFile(Client tc, String filepath, String index, String id) throws Exception {
        uploadFile(tc, filepath, index, id, false);
    }

    public static void uploadFile(Client tc, String filepath, String index, String id, boolean populateEmptyIfFileMissing) throws Exception {
        LOGGER.info("Will update '" + id + "' with " + filepath + " and populate it with empty doc if file missing and populateEmptyIfFileMissing=" + populateEmptyIfFileMissing);
        try (Reader reader = ConfigHelper.createFileOrStringReader(filepath, populateEmptyIfFileMissing)) {

            final String res = tc
                    .index(new IndexRequest(index).type("security").id(id).setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                            .source(id, readXContent(reader, XContentType.YAML))).actionGet().getId();

            if (!id.equals(res)) {
                throw new Exception("   FAIL: Configuration for '" + id
                        + "' failed for unknown reasons. Pls. consult logfile of elasticsearch");
            }
        }
    }

    private static Reader createFileOrStringReader(String filepath, boolean populateEmptyIfFileMissing) throws Exception {
        Reader reader;
        if (populateEmptyIfFileMissing) {
            File file = new File(filepath);
            reader = file.exists() ? new FileReader(filepath) : new StringReader(ConfigHelper.emptyYamlConfig());
        } else {
            reader = new FileReader(filepath);
        }
        return reader;
    }

    public static String fileContentOrEmptyIfMissing(final String filepath, final boolean populateEmptyIfMissing) throws Exception {
        File file = new File(filepath);
        if (!file.exists() && populateEmptyIfMissing) {
            return ConfigHelper.emptyYamlConfig();
        }
        return Files.asCharSource(new File(filepath), StandardCharsets.UTF_8).read();
    }

    public static String emptyYamlConfig() {
        return "{}";
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
        
        //validate
        Settings.builder().loadFromStream("dummy.json", new ByteArrayInputStream(BytesReference.toBytes(retVal)), true).build();
        return retVal;
    }

}
