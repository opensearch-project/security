/*
 * Copyright 2018 floragunn GmbH
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

package com.floragunn.searchguard.compliance;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.settings.Settings;
import org.joda.time.format.DateTimeFormat;

import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.support.WildcardMatcher;


public final class ComplianceConfig {

    private final Logger log = LogManager.getLogger(getClass());
    private final Settings settings;
    private final Map<String, Set<String>> indexFields = new HashMap<>();

    public ComplianceConfig(Settings settings) {
        super();
        this.settings = settings;
        final List<String> piiFields = this.settings.getAsList(ConfigConstants.SEARCHGUARD_COMPLIANCE_PII_FIELDS,
                Collections.emptyList(), false);

        //searchguard.compliance.pii_fields:
        //  - indexpattern,fieldpattern,fieldpattern,....
        for(String pii: piiFields) {
            final List<String> split = new ArrayList<>(Arrays.asList(pii.split(",")));
            if(split.isEmpty()) {
                continue;
            } else if(split.size() == 1) {
                indexFields.put(split.get(0), Collections.singleton("*"));
            } else {
                Set<String> _fields = new HashSet<String>(split.subList(1, split.size()));
                indexFields.put(split.get(0), _fields);
            }
        }

        final String type = settings.get(ConfigConstants.SEARCHGUARD_AUDIT_TYPE, null);
        if("internal_elasticsearch".equalsIgnoreCase(type)) {
            final String index = settings.get(ConfigConstants.SEARCHGUARD_AUDIT_CONFIG_INDEX,"'sg6-auditlog-'YYYY.MM.dd");
            try {
                DateTimeFormat.forPattern(index); //throws IllegalArgumentException if no pattern
                int first = index.indexOf("'");
                String _index = index.substring( first + 1, index.indexOf("'", first+1));
                checkAndRemoveAuditlogIndex(_index);
            } catch (IllegalArgumentException e) {
                //no pattern
                checkAndRemoveAuditlogIndex(index);
            } catch (Exception e) {
                log.error("Unable to check if auditlog index {} is part of compliance setup", index, e);
            }
        }

        log.info("PII configuration: "+indexFields);
    }

    private void checkAndRemoveAuditlogIndex(String _index) {
        for(String indexPattern: new HashSet<>(indexFields.keySet())) {
            if(WildcardMatcher.match(indexPattern, _index)) {
                indexFields.remove(indexPattern);
                log.warn("Removed "+indexPattern+" from PII configuration");
            }
        }
    }

    //cache this
    private Set<String> get(String index) {
        final Set<String> tmp = new HashSet<String>();
        for(String indexPattern: indexFields.keySet()) {
            if(WildcardMatcher.match(indexPattern, index)) {
                tmp.addAll(indexFields.get(indexPattern));
            }
        }
        return tmp;
    }

    public boolean enabledForIndex(String index) {
        return !get(index).isEmpty();
    }

    public boolean enabledForField(String index, String field) {
        final Set<String> fields = get(index);
        if(fields.isEmpty()) {
            return false;
        }

        return WildcardMatcher.matchAny(fields, field);
    }

    public boolean logDiffsOnly() {
        return false;
    }

    public boolean logMetadataOnly() {
        return false;
    }
}
