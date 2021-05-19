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

package org.opensearch.security.securityconf.impl.v6;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import org.opensearch.security.securityconf.Hideable;

public class RoleV6 implements Hideable {

    private boolean readonly;
    private boolean hidden;
    private List<String> cluster = Collections.emptyList();
    private Map<String, String> tenants = Collections.emptyMap();
    private Map<String, Index> indices = Collections.emptyMap();

    public static class Index {

        @JsonIgnore
        private final Map<String, List<String>> types = new HashMap<>();

        @JsonAnySetter
        void setTypes0(String key, List<String> value) {
            types.put(key, value);
        }

        @JsonAnyGetter
        public Map<String, List<String>> getTypes() {
            return types;
        }
        
        private String _dls_;
        private List<String> _fls_;
        private List<String> _masked_fields_;

        
        
        public String get_dls_() {
            return _dls_;
        }

        public List<String> get_fls_() {
            return _fls_;
        }

        public List<String> get_masked_fields_() {
            return _masked_fields_;
        }

        @Override
        public String toString() {
            return "Index [types=" + types + ", _dls_=" + _dls_ + ", _fls_=" + _fls_ + ", _masked_fields_=" + _masked_fields_ + "]";
        }

        

    }

    public boolean isReadonly() {
        return readonly;
    }

    public void setReadonly(boolean readonly) {
        this.readonly = readonly;
    }

    public boolean isHidden() {
        return hidden;
    }

    public void setHidden(boolean hidden) {
        this.hidden = hidden;
    }

    public List<String> getCluster() {
        return cluster;
    }

    public void setCluster(List<String> cluster) {
        this.cluster = cluster;
    }

    public Map<String, String> getTenants() {
        return tenants;
    }

    public void setTenants(Map<String, String> tenants) {
        this.tenants = tenants;
    }

    public Map<String, Index> getIndices() {
        return indices;
    }

    public void setIndices(Map<String, Index> indices) {
        this.indices = indices;
    }

    @Override
    public String toString() {
        return "Role [readonly=" + readonly + ", hidden=" + hidden + ", cluster=" + cluster + ", tenants=" + tenants + ", indices=" + indices + "]";
    }
    
    @JsonIgnore
    public boolean isReserved() {
        return readonly;
    }

}