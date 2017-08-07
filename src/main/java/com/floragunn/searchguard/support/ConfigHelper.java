/*
 * Copyright 2017 floragunn Gmbh
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package com.floragunn.searchguard.support;

import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.support.WriteRequest.RefreshPolicy;
import org.elasticsearch.client.Client;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.settings.loader.JsonSettingsLoader;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.XContentType;

public class ConfigHelper {
    
    private static final Logger LOGGER = LogManager.getLogger(ConfigHelper.class);
    
    public static void uploadFile(Client tc, String filepath, String index, String type) throws Exception {
        LOGGER.info("Will update '" + type + "' with " + filepath);
        try (Reader reader = new FileReader(filepath)) {

            final String id = tc
                    .index(new IndexRequest(index).type(type).id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                            .source(type, readXContent(reader, XContentType.YAML))).actionGet().getId();

            if ("0".equals(id)) {
                //System.out.println("   SUCC: Configuration for '" + type + "' created or updated");
            } else {
                throw new Exception("   FAIL: Configuration for '" + type
                        + "' failed for unknown reasons. Pls. consult logfile of elasticsearch");
            }
        } catch (Exception e) {
            throw e;
        }
    }
    
    public static BytesReference readXContent(final Reader reader, final XContentType xContentType) throws IOException {
        BytesReference retVal;
        XContentParser parser = null;
        try {
            parser = XContentFactory.xContent(xContentType).createParser(NamedXContentRegistry.EMPTY, reader);
            parser.nextToken();
            final XContentBuilder builder = XContentFactory.jsonBuilder();
            builder.copyCurrentStructure(parser);
            retVal = builder.bytes();
        } finally {
            if (parser != null) {
                parser.close();
            }
        }
        
        //validate
        Settings.builder().put(new JsonSettingsLoader(true).load(XContentHelper.createParser(NamedXContentRegistry.EMPTY, retVal, XContentType.JSON))).build();
        return retVal;
    }

}
