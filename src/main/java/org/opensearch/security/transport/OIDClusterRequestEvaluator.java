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

package org.opensearch.security.transport;

import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.opensearch.common.settings.Settings;
import org.opensearch.transport.TransportRequest;

import org.opensearch.security.support.ConfigConstants;

/**
 * Implementation to evaluate a certificate extension with a given OID
 * and value to the same value found on the peer certificate
 *
 */
public final class OIDClusterRequestEvaluator implements InterClusterRequestEvaluator {
    private final String certOid;

    public OIDClusterRequestEvaluator(final Settings settings) {
        this.certOid = settings.get(ConfigConstants.OPENDISTRO_SECURITY_CERT_OID, "1.2.3.4.5.5");
    }

    @Override
    public boolean isInterClusterRequest(TransportRequest request, X509Certificate[] localCerts, X509Certificate[] peerCerts,
            final String principal) {
        if (localCerts != null && localCerts.length > 0 && peerCerts != null && peerCerts.length > 0) {
            final byte[] localValue = localCerts[0].getExtensionValue(certOid);
            final byte[] peerValue = peerCerts[0].getExtensionValue(certOid);
            if (localValue != null && peerValue != null) {
                return Arrays.equals(localValue, peerValue);
            }
        }
        return false;
    }

}
