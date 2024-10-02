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
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.securityconf.impl.v7;

import java.util.Collections;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;

import org.opensearch.security.securityconf.Hideable;
import org.opensearch.security.securityconf.StaticDefinable;

public class RoleV7 implements Hideable, StaticDefinable {

    private boolean reserved;
    private boolean hidden;
    @JsonProperty(value = "static")
    private boolean _static;
    private String description;
    private List<String> cluster_permissions = Collections.emptyList();
    private List<Index> index_permissions = Collections.emptyList();
    private List<Tenant> tenant_permissions = Collections.emptyList();

    public RoleV7() {

    }

    public static class Index {

        private List<String> index_patterns = Collections.emptyList();
        private String dls;
        private List<String> fls = Collections.emptyList();
        private List<String> masked_fields = Collections.emptyList();
        private List<String> allowed_actions = Collections.emptyList();

        public Index() {
            super();
        }

        public List<String> getIndex_patterns() {
            return index_patterns;
        }

        public void setIndex_patterns(List<String> index_patterns) {
            this.index_patterns = index_patterns;
        }

        public String getDls() {
            return dls;
        }

        public void setDls(String dls) {
            this.dls = dls;
        }

        public List<String> getFls() {
            return fls;
        }

        public void setFls(List<String> fls) {
            this.fls = fls;
        }

        public List<String> getMasked_fields() {
            return masked_fields;
        }

        public void setMasked_fields(List<String> masked_fields) {
            this.masked_fields = masked_fields;
        }

        public List<String> getAllowed_actions() {
            return allowed_actions;
        }

        public void setAllowed_actions(List<String> allowed_actions) {
            this.allowed_actions = allowed_actions;
        }

        @Override
        public String toString() {
            return "Index [index_patterns="
                + index_patterns
                + ", dls="
                + dls
                + ", fls="
                + fls
                + ", masked_fields="
                + masked_fields
                + ", allowed_actions="
                + allowed_actions
                + "]";
        }
    }

    public static class Tenant {

        private List<String> tenant_patterns = Collections.emptyList();
        private List<String> allowed_actions = Collections.emptyList();

        /*public Index(String pattern, RoleV6.Index v6Index) {
            super();
            index_patterns = Collections.singletonList(pattern);
            dls = v6Index.get_dls_();
            fls = v6Index.get_fls_();
            masked_fields = v6Index.get_masked_fields_();
            Set<String> tmpActions = new HashSet<>();
            for(Entry<String, List<String>> type: v6Index.getTypes().entrySet()) {
                tmpActions.addAll(type.getValue());
            }
            allowed_actions = new ArrayList<>(tmpActions);
        }*/

        public Tenant() {
            super();
        }

        public List<String> getTenant_patterns() {
            return tenant_patterns;
        }

        public void setTenant_patterns(List<String> tenant_patterns) {
            this.tenant_patterns = tenant_patterns;
        }

        public List<String> getAllowed_actions() {
            return allowed_actions;
        }

        public void setAllowed_actions(List<String> allowed_actions) {
            this.allowed_actions = allowed_actions;
        }

        @Override
        public String toString() {
            return "Tenant [tenant_patterns=" + tenant_patterns + ", allowed_actions=" + allowed_actions + "]";
        }

    }

    public boolean isHidden() {
        return hidden;
    }

    public void setHidden(boolean hidden) {
        this.hidden = hidden;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public List<String> getCluster_permissions() {
        return cluster_permissions;
    }

    public void setCluster_permissions(List<String> cluster_permissions) {
        this.cluster_permissions = cluster_permissions;
    }

    public List<Index> getIndex_permissions() {
        return index_permissions;
    }

    public void setIndex_permissions(List<Index> index_permissions) {
        this.index_permissions = index_permissions;
    }

    public List<Tenant> getTenant_permissions() {
        return tenant_permissions;
    }

    public void setTenant_permissions(List<Tenant> tenant_permissions) {
        this.tenant_permissions = tenant_permissions;
    }

    public boolean isReserved() {
        return reserved;
    }

    public void setReserved(boolean reserved) {
        this.reserved = reserved;
    }

    @JsonProperty(value = "static")
    public boolean isStatic() {
        return _static;
    }

    @JsonProperty(value = "static")
    public void setStatic(boolean _static) {
        this._static = _static;
    }

    @Override
    public String toString() {
        return "RoleV7 [reserved="
            + reserved
            + ", hidden="
            + hidden
            + ", _static="
            + _static
            + ", description="
            + description
            + ", cluster_permissions="
            + cluster_permissions
            + ", index_permissions="
            + index_permissions
            + ", tenant_permissions="
            + tenant_permissions
            + "]";
    }

}
