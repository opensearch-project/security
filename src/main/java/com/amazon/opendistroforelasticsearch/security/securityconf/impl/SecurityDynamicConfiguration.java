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
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.xcontent.ToXContent;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.common.xcontent.XContentType;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.introspect.BeanPropertyDefinition;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.ser.BeanPropertyWriter;
import com.fasterxml.jackson.databind.ser.BeanSerializer;
import com.fasterxml.jackson.databind.type.TypeFactory;

import com.amazon.opendistroforelasticsearch.security.DefaultObjectMapper;
import com.amazon.opendistroforelasticsearch.security.NonValidatingObjectMapper;
import com.amazon.opendistroforelasticsearch.security.securityconf.Hashed;
import com.amazon.opendistroforelasticsearch.security.securityconf.Hideable;
import com.amazon.opendistroforelasticsearch.security.securityconf.StaticDefinable;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v6.ConfigV6;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7.ConfigV7;

public class SecurityDynamicConfiguration<T> implements ToXContent {
    
    private static final TypeReference<HashMap<String,Object>> typeRefMSO = new TypeReference<HashMap<String,Object>>() {};
    private static final String TRANSIENT = "transient";
    public static final ToXContent.MapParams TRANSIENT_PARAMS = new ToXContent.MapParams(Collections.singletonMap(TRANSIENT, "true"));
    private static final ObjectMapper objectMapper = createObjectMapper();

    private static ObjectMapper createObjectMapper() {
        final ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        objectMapper.enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
        return registerModule(objectMapper);
    }

    private static ObjectMapper registerModule(ObjectMapper objectMapper) {
        final SimpleModule module = new SimpleModule();
        module.addSerializer(ConfigV7.Kibana.class, createSerializer(objectMapper, ConfigV7.Kibana.class));
        module.addSerializer(ConfigV6.Kibana.class, createSerializer(objectMapper, ConfigV6.Kibana.class));
        return objectMapper.registerModule(module);
    }

    private static JsonSerializer createSerializer(ObjectMapper objectMapper, Class cls) {
        final TypeFactory typeFactory = objectMapper.getTypeFactory();
        final JavaType type = typeFactory.constructType(cls);
        final List<BeanPropertyDefinition> properties = objectMapper.getSerializationConfig().introspect(type).findProperties();
        final BeanPropertyWriter[] beanPropertyWriters = properties.stream()
                .map(p -> new BeanPropertyWriter(p, p.getPrimaryMember(), null, p.getPrimaryType(), null, null, null, false, null, null))
                .toArray(size -> new BeanPropertyWriter[size]);
        return new BeanSerializer(type, null, beanPropertyWriters, null);
    }

    @JsonIgnore
    private final Map<String, T> centries = new HashMap<>();
    private long seqNo= -1;
    private long primaryTerm= -1;
    private CType ctype;
    private int version = -1;
    
    public static <T> SecurityDynamicConfiguration<T> empty() {
        return new SecurityDynamicConfiguration<T>();
    }

    public static <T> SecurityDynamicConfiguration<T> fromJson(String json, CType ctype, int version, long seqNo, long primaryTerm) throws IOException {
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
        return fromJson(DefaultObjectMapper.writeValueAsString(json, false), ctype, version, seqNo, primaryTerm);
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
        String json;
        if (params == null) {
            json = DefaultObjectMapper.writeValueAsString(this, false);
        } else if (params.paramAsBoolean(TRANSIENT, false)) {
            json = DefaultObjectMapper.writeValueAsString(objectMapper, this);
        } else {
            json = DefaultObjectMapper.writeValueAsString(this, params.paramAsBoolean("omit_defaults", false));
        }
        return builder.map(DefaultObjectMapper.readValue(json, typeRefMSO));
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
            return fromJson(DefaultObjectMapper.writeValueAsString(this, false), ctype, version, seqNo, primaryTerm);
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

}
