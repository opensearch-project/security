/*
 * Copyright 2015-2018 floragunn GmbH
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

package org.opensearch.security.support;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeType;
import org.opensearch.security.DefaultObjectMapper;

public final class SecurityJsonNode {
    
    private final JsonNode node;

    public SecurityJsonNode(JsonNode node) {
        this.node = node;
    }
    
    public SecurityJsonNode get(String name) {
        if(isNull(node)) {
            return new SecurityJsonNode(null);
        }
        
        JsonNode val = node.get(name);
        return new SecurityJsonNode(val);
    }
    
    public String asString() {
        if(isNull(node)) {
            return null;
        } else {
            return node.asText(null);
        }
    }
    
    private static boolean isNull(JsonNode node) {
        return node == null || node.isNull();
    }
    
    public boolean isNull() {
        return isNull(this.node);
    }

    public SecurityJsonNode get(int i) {
        if(isNull(node) || node.getNodeType() != JsonNodeType.ARRAY || i > (node.size() -1)) {
            return new SecurityJsonNode(null);
        }

        return new SecurityJsonNode(node.get(i));
    }

    public SecurityJsonNode getDotted(String string) {
        SecurityJsonNode tmp = this;
        for(String part: string.split("\\.")) {
            tmp = tmp.get(part);
        }
        
        return tmp;
        
    }

    public List<String> asList() {
        if(isNull(node) || node.getNodeType() != JsonNodeType.ARRAY) {
            return null;
        }
        
        List<String> retVal = new ArrayList<String>();
        
        for(int i=0; i<node.size(); i++) {
            retVal.add(node.get(i).asText());
        }
        
        return Collections.unmodifiableList(retVal);
    }
    
    public static SecurityJsonNode fromJson(String json) throws IOException {
        return new SecurityJsonNode(DefaultObjectMapper.readTree(json));
    }
}
