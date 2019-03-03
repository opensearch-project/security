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

package com.amazon.opendistroforelasticsearch.security.transport;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.transport.TransportRequest;

import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.support.WildcardMatcher;

public final class DefaultInterClusterRequestEvaluator implements InterClusterRequestEvaluator {

    private final Logger log = LogManager.getLogger(this.getClass());
    private final String certOid;
    private final List<String> nodesDn;

    public DefaultInterClusterRequestEvaluator(final Settings settings) {
        this.certOid = settings.get(ConfigConstants.OPENDISTRO_SECURITY_CERT_OID, "1.2.3.4.5.5");
        this.nodesDn = settings.getAsList(ConfigConstants.OPENDISTRO_SECURITY_NODES_DN, Collections.emptyList());
    }

    @Override
    public boolean isInterClusterRequest(TransportRequest request, X509Certificate[] localCerts, X509Certificate[] peerCerts,
            final String principal) {
        
        String[] principals = new String[2];
        
        if (principal != null && principal.length() > 0) {
            principals[0] = principal;
            principals[1] = principal.replace(" ","");
        }
        
        if (principals[0] != null && WildcardMatcher.matchAny(nodesDn, principals, true)) {
            
            if (log.isTraceEnabled()) {
                log.trace("Treat certificate with principal {} as other node because of it matches one of {}", Arrays.toString(principals),
                        nodesDn);
            }
            
            return true;
            
        } else {
            if (log.isTraceEnabled()) {
                log.trace("Treat certificate with principal {} NOT as other node because we it does not matches one of {}", Arrays.toString(principals),
                        nodesDn);
            }
        }

        try {
            final Collection<List<?>> ianList = peerCerts[0].getSubjectAlternativeNames();
            if (ianList != null) {
                final StringBuilder sb = new StringBuilder();

                for (final List<?> ian : ianList) {

                    if (ian == null) {
                        continue;
                    }

                    for (@SuppressWarnings("rawtypes")
                    final Iterator iterator = ian.iterator(); iterator.hasNext();) {
                        final int id = (int) iterator.next();
                        if (id == 8) { // id 8 = OID, id 1 = name (as string or
                                       // ASN.1 encoded byte[])
                            Object value = iterator.next();

                            if (value == null) {
                                continue;
                            }

                            if (value instanceof String) {
                                sb.append(id + "::" + value);
                            } else if (value instanceof byte[]) {
                                log.error("Unable to handle OID san {} with value {} of type byte[] (ASN.1 DER not supported here)", id,
                                        Arrays.toString((byte[]) value));
                            } else {
                                log.error("Unable to handle OID san {} with value {} of type {}", id, value, value.getClass());
                            }
                        } else {
                            iterator.next();
                        }
                    }
                }

                if (sb.indexOf("8::" + this.certOid) >= 0) {
                    return true;
                }

            } else {
                if (log.isTraceEnabled()) {
                    log.trace("No subject alternative names (san) found");
                }
            }
        } catch (CertificateParsingException e) {
            if (log.isDebugEnabled()) {
                log.debug("Exception parsing certificate using {}", e, this.getClass());
            }
            throw new ElasticsearchException(e);
        }
        return false;
    }

}
