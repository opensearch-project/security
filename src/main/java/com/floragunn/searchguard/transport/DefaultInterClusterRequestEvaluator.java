/*
 * Copyright 2017 floragunn UG (haftungsbeschränkt)
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
package com.floragunn.searchguard.transport;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.transport.TransportRequest;

public class DefaultInterClusterRequestEvaluator implements InterClusterRequestEvaluator {

    private final ESLogger log = Loggers.getLogger(this.getClass());
    private final String certOid;
    
    public DefaultInterClusterRequestEvaluator(final Settings settings) {
        this.certOid = settings.get("searchguard.cert.oid", "1.2.3.4.5.5");
    }

    @Override
    public boolean isInterClusterRequest(TransportRequest request, X509Certificate[] localCerts, X509Certificate[] peerCerts) {
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
                        if (id == 8) { //id 8 = OID, id 1 = name (as string or ASN.1 encoded byte[])
                            Object value = iterator.next();
                            
                            if(value == null) {
                                continue;
                            }
                            
                            if(value instanceof String) {
                                sb.append(id + "::" + value);
                            } else if(value instanceof byte[]) {
                                log.error("Unable to handle OID san {} with value {} of type byte[] (ASN.1 DER not supported here)", id, Arrays.toString((byte[]) value));
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
        }catch(CertificateParsingException e) {
            if(log.isDebugEnabled()) {
                log.debug("Exception parsing certificate using {}", e, this.getClass());
            }
            throw new ElasticsearchException(e);
        }
        return false;
    }

}
