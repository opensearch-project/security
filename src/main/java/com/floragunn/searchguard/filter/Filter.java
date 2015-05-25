/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
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

package com.floragunn.searchguard.filter;

import java.io.Serializable;
import java.util.Set;

// THIS CLASS IS NOT USED YET
// TODO Will be used in the future to store filter configuration in an index
public class Filter implements Serializable {

    private Type type;
    private String name;
    private Set<String> allowed_actions;
    private Set<String> forbidden_actions;
    private DlsType dls_type;
    private String field;
    private String value;
    private boolean negate;
    private Set<String> source_includes;
    private Set<String> source_excludes;

    public enum Type {
        DLS("dls"), FLS("fls"), ACTION_REQ("action_req"), REST_REQ("rest_req");

        private final String text;

        private Type(final String text) {
            this.text = text;
        }

        @Override
        public String toString() {
            return text;
        }
    }

    public enum DlsType {
        EXISTS("exists"), TERM("term"), USER_NAME("user_name"), USER_ROLES("user_roles"), LDAP_USER_ATTRIBUTE("ldap_user_attribute"), LDAP_USER_ROLES(
                "ldap_user_roles");

        private final String text;

        private DlsType(final String text) {
            this.text = text;
        }

        @Override
        public String toString() {
            return text;
        }
    }

    public final Type getType() {
        return type;
    }

    public final void setType(final Type type) {
        this.type = type;
    }

    public final String getName() {
        return name;
    }

    public final void setName(final String name) {
        this.name = name;
    }

    public final Set<String> getAllowed_actions() {
        return allowed_actions;
    }

    public final void setAllowed_actions(final Set<String> allowed_actions) {
        this.allowed_actions = allowed_actions;
    }

    public final Set<String> getForbidden_actions() {
        return forbidden_actions;
    }

    public final void setForbidden_actions(final Set<String> forbidden_actions) {
        this.forbidden_actions = forbidden_actions;
    }

    public final DlsType getDls_type() {
        return dls_type;
    }

    public final void setDls_type(final DlsType dls_type) {
        this.dls_type = dls_type;
    }

    public final String getField() {
        return field;
    }

    public final void setField(final String field) {
        this.field = field;
    }

    public final String getValue() {
        return value;
    }

    public final void setValue(final String value) {
        this.value = value;
    }

    public final boolean isNegate() {
        return negate;
    }

    public final void setNegate(final boolean negate) {
        this.negate = negate;
    }

    public final Set<String> getSource_includes() {
        return source_includes;
    }

    public final void setSource_includes(final Set<String> source_includes) {
        this.source_includes = source_includes;
    }

    public final Set<String> getSource_excludes() {
        return source_excludes;
    }

    public final void setSource_excludes(final Set<String> source_excludes) {
        this.source_excludes = source_excludes;
    }

}
