/*
 * Copyright 2015-2017 floragunn GmbH
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
/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.securityconf.impl;

import java.io.IOException;
import java.io.Reader;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import com.amazon.opendistroforelasticsearch.security.support.OpenDistroSecurityUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.ToXContent;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.common.xcontent.XContentType;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.amazon.opendistroforelasticsearch.security.DefaultObjectMapper;
import com.amazon.opendistroforelasticsearch.security.NonValidatingObjectMapper;
import com.amazon.opendistroforelasticsearch.security.securityconf.Hashed;
import com.amazon.opendistroforelasticsearch.security.securityconf.Hideable;
import com.amazon.opendistroforelasticsearch.security.securityconf.StaticDefinable;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7.RoleV7;

public class SecurityDynamicConfiguration<T> implements ToXContent {

    private static final Logger log = LogManager.getLogger(SecurityDynamicConfiguration.class);
    
    private static final TypeReference<HashMap<String,Object>> typeRefMSO = new TypeReference<HashMap<String,Object>>() {};

    @JsonIgnore
    private final Map<String, T> centries = new HashMap<>();
    private long seqNo= -1;
    private long primaryTerm= -1;
    private CType ctype;
    private int version = -1;
    private long docVersion = -1;
    private String uninterpolatedJson;
    
    public static <T> SecurityDynamicConfiguration<T> empty() {
        return new SecurityDynamicConfiguration<T>();
    }

    public static <T> SecurityDynamicConfiguration<T> fromJson(String json, CType ctype, int version, long docVersion, long seqNo, long primaryTerm) throws IOException {
        return fromJson(json, ctype, version, seqNo, primaryTerm, false);
    }

    public static <T> SecurityDynamicConfiguration<T> fromJson(String json, CType ctype, int version, long seqNo, long primaryTerm, boolean acceptInvalid) throws IOException {
        SecurityDynamicConfiguration<T> sdc = null;
        if(ctype != null) {
            final Class<?> implementationClass = ctype.getImplementationClass().get(version);
            if(implementationClass == null) {
                throw new IllegalArgumentException("No implementation class found for "+ctype+" and config version "+version);
            }
            if(acceptInvalid && version < 2) {
                sdc = NonValidatingObjectMapper.readValue(json, NonValidatingObjectMapper.getTypeFactory().constructParametricType(SecurityDynamicConfiguration.class, implementationClass));
            } else {
                sdc = DefaultObjectMapper.readValue(json, DefaultObjectMapper.getTypeFactory().constructParametricType(SecurityDynamicConfiguration.class, implementationClass));
            }
            validate(sdc, version, ctype);
        
        } else {
            sdc = new SecurityDynamicConfiguration<T>();
        }
        
        sdc.ctype = ctype;
        sdc.seqNo = seqNo;
        sdc.primaryTerm = primaryTerm;
        sdc.version = version;
        sdc.docVersion = -1;

        return sdc;
    }
    
    public static void validate(SecurityDynamicConfiguration sdc, int version, CType ctype) throws IOException {
        if(version < 2 && sdc.get_meta() != null) {
            throw new IOException("A version of "+version+" can not have a _meta key for "+ctype);
        }
        
        if(version >= 2 && sdc.get_meta() == null) {
            throw new IOException("A version of "+version+" must have a _meta key for "+ctype);
        }
        
        if(version < 2 && ctype == CType.CONFIG && (sdc.getCEntries().size() != 1 || !sdc.getCEntries().keySet().contains("opendistro_security"))) {
            throw new IOException("A version of "+version+" must have a single toplevel key named 'opendistro_security' for "+ctype);
        }
        
        if(version >= 2 && ctype == CType.CONFIG && (sdc.getCEntries().size() != 1 || !sdc.getCEntries().keySet().contains("config"))) {
            throw new IOException("A version of "+version+" must have a single toplevel key named 'config' for "+ctype);
        }
        
    }

    public static <T> SecurityDynamicConfiguration<T> fromNode(JsonNode json, CType ctype, int version, long seqNo, long primaryTerm) throws IOException {
        return fromJson(DefaultObjectMapper.writeValueAsString(json, false), ctype, version, -1, seqNo, primaryTerm);
    }

    public static <T> SecurityDynamicConfiguration<T> fromNode(JsonNode json, CType ctype, int version, long docVersion, long seqNo, long primaryTerm) throws IOException {
        return fromJson(DefaultObjectMapper.writeValueAsString(json, false), null, ctype, version, docVersion, seqNo, primaryTerm);
    }

    public static <T> SecurityDynamicConfiguration<T> fromJson(String uninterpolatedJson, CType ctype, long docVersion, long seqNo, long primaryTerm, Settings settings) throws IOException {

        String jsonString = OpenDistroSecurityUtils.replaceEnvVars(uninterpolatedJson, settings);
        JsonNode jsonNode = DefaultObjectMapper.readTree(jsonString);
        int configVersion = 1;

        if (jsonNode.get("_sg_meta") != null) {
            assert jsonNode.get("_sg_meta").get("type").asText().equals(ctype.toLCString());
            configVersion = jsonNode.get("_sg_meta").get("config_version").asInt();
        }

        if (log.isDebugEnabled()) {
            log.debug("Load " + ctype + " with version " + configVersion);
        }


        try {
            return SecurityDynamicConfiguration.fromJson(jsonString, ctype, configVersion, docVersion, seqNo, primaryTerm);
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("Unable to load " + ctype + " with version " + configVersion + " - Try loading legacy format ...");
            }
            return SecurityDynamicConfiguration.fromJson(jsonString, ctype, 0, docVersion, seqNo, primaryTerm);
        }
    }

    public static <T> SecurityDynamicConfiguration<T> fromJson(String json, String uninterpolatedJson, CType ctype, int version, long docVersion, long seqNo, long primaryTerm) throws IOException {
        SecurityDynamicConfiguration<T> sdc;
        if(ctype != null) {
            final Class<?> implementationClass = ctype.getImplementationClass().get(version);
            if(implementationClass == null) {
                throw new IllegalArgumentException("No implementation class found for "+ctype+" and config version "+version);
            }
            sdc = DefaultObjectMapper.readValue(json, DefaultObjectMapper.getTypeFactory().constructParametricType(SecurityDynamicConfiguration.class, implementationClass));

            validate(sdc, version, ctype);

        } else {
            sdc = new SecurityDynamicConfiguration<T>();
        }

        sdc.ctype = ctype;
        sdc.seqNo = seqNo;
        sdc.primaryTerm = primaryTerm;
        sdc.docVersion = docVersion;
        sdc.version = version;
        sdc.uninterpolatedJson = uninterpolatedJson;

        return sdc;
    }

    //for Jackson
    private SecurityDynamicConfiguration() {
        super();
    }
    
    private Meta _meta;

    public Meta get_meta() {
        return _meta;
    }

    public void set_meta(Meta _meta) {
        this._meta = _meta;
    }

    
    @JsonAnySetter
    void setCEntries(String key, T value) {
        putCEntry(key, value);
    }
    
    @JsonAnyGetter
    public Map<String, T> getCEntries() {
        return centries;
    }
    
    @JsonIgnore
    public void removeHidden() {
        for(Entry<String, T> entry: new HashMap<String, T>(centries).entrySet()) {
            if(entry.getValue() instanceof Hideable && ((Hideable) entry.getValue()).isHidden()) {
                centries.remove(entry.getKey());
            }
        }
    }
    
    @JsonIgnore
    public void removeStatic() {
        for(Entry<String, T> entry: new HashMap<String, T>(centries).entrySet()) {
            if(entry.getValue() instanceof StaticDefinable && ((StaticDefinable) entry.getValue()).isStatic()) {
                centries.remove(entry.getKey());
            }
        }
    }
    
    @JsonIgnore
    public void clearHashes() {
        for(Entry<String, T> entry: centries.entrySet()) {
            if(entry.getValue() instanceof Hashed) {
               ((Hashed) entry.getValue()).clearHash(); 
            }
        }
    }
    

    public void removeOthers(String key) {
        T tmp = this.centries.get(key);
        this.centries.clear();
        this.centries.put(key, tmp);
    }
    
    @JsonIgnore
    public T putCEntry(String key, T value) {
        return centries.put(key, value);
    }
    
    @JsonIgnore
    public void putCObject(String key, Object value) {
        centries.put(key, (T) value);
    }
    
    @JsonIgnore
    public T getCEntry(String key) {
        return centries.get(key);
    }
    
    @JsonIgnore
    public boolean exists(String key) {
        return centries.containsKey(key);
    }

    @JsonIgnore
    public BytesReference toBytesReference() throws IOException {
        return XContentHelper.toXContent(this, XContentType.JSON, false);
    }

    @Override
    public String toString() {
        return "SecurityDynamicConfiguration [seqNo=" + seqNo + ", primaryTerm=" + primaryTerm + ", ctype=" + ctype + ", version=" + version + ", centries="
                + centries + ", getImplementingClass()=" + getImplementingClass() + "]";
    }

    @Override
    @JsonIgnore
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        final boolean omitDefaults = params != null && params.paramAsBoolean("omit_defaults", false);
        return builder.map(DefaultObjectMapper.readValue(DefaultObjectMapper.writeValueAsString(this, omitDefaults), typeRefMSO));
    }
    
    @Override
    @JsonIgnore
    public boolean isFragment() {
        return false;
    }

    @JsonIgnore
    public long getSeqNo() {
        return seqNo;
    }

    @JsonIgnore
    public long getPrimaryTerm() {
        return primaryTerm;
    }

    @JsonIgnore
    public CType getCType() {
        return ctype;
    }
    
    @JsonIgnore
    public void setCType(CType ctype) {
        this.ctype = ctype;
    }

    @JsonIgnore
    public int getVersion() {
        return version;
    }
    
    @JsonIgnore
    public Class<?> getImplementingClass() {
        return ctype==null?null:ctype.getImplementationClass().get(getVersion());
    }

    @JsonIgnore
    public SecurityDynamicConfiguration<T> deepClone() {
        try {
            return fromJson(DefaultObjectMapper.writeValueAsString(this, false), ctype, version, -1, seqNo, primaryTerm);
        } catch (Exception e) {
            throw ExceptionsHelper.convertToElastic(e);
        }
    }

    @JsonIgnore
    public void remove(String key) {
       centries.remove(key);
        
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    public boolean add(SecurityDynamicConfiguration other) {
        if(other.ctype == null || !other.ctype.equals(this.ctype)) {
            return false;
        }
        
        if(other.getImplementingClass() == null || !other.getImplementingClass().equals(this.getImplementingClass())) {
            return false;
        }
        
        if(other.version != this.version) {
            return false;
        }
        
        this.centries.putAll(other.centries);
        return true;
    }
    
    @JsonIgnore
    @SuppressWarnings({ "rawtypes" })
    public boolean containsAny(SecurityDynamicConfiguration other) {
        return !Collections.disjoint(this.centries.keySet(), other.centries.keySet());
    }

    public boolean isHidden(String resourceName){
        final Object o = centries.get(resourceName);
        return o != null && o instanceof Hideable && ((Hideable) o).isHidden();
    }

    @JsonIgnore
    public long getDocVersion() {
        return docVersion;
    }

    @JsonIgnore
    public String getUninterpolatedJson() {
        return uninterpolatedJson;
    }

}
