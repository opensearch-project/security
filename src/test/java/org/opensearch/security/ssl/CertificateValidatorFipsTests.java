/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2017 floragunn GmbH
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

package org.opensearch.security.ssl;

import java.security.Security;

import org.junit.AfterClass;
import org.junit.BeforeClass;

/**
 * FIPS variant of {@link CertificateValidatorTest}. The BC FIPS CertPath implementation
 * words its revocation failures differently from the JDK one, and reports a missing CRL
 * rather than treating the certificate as revoked.
 */
public class CertificateValidatorFipsTests extends CertificateValidatorTest {

    private static final String BC_ENABLE_CRLDP = "org.bouncycastle.x509.enableCRLDP";

    private static String previousEnableCrldp;

    /**
     * BouncyCastle FIPS fetches CRLs from distribution points only when this property is set; the plugin leaves it to the
     * java.security file. The tests set it the way an operator would and restore it afterwards.
     */
    @BeforeClass
    public static void enableCrlDistributionPoints() {
        previousEnableCrldp = Security.getProperty(BC_ENABLE_CRLDP);
        Security.setProperty(BC_ENABLE_CRLDP, "true");
    }

    @AfterClass
    public static void restoreCrlDistributionPoints() {
        // A security property cannot be removed, so an unset property becomes "false", which BouncyCastle treats the same.
        Security.setProperty(BC_ENABLE_CRLDP, previousEnableCrldp == null ? "false" : previousEnableCrldp);
    }

    @Override
    protected String getRevokedCertificateMessage() {
        return "Certificate revocation after";
    }

    @Override
    protected String getNoCrlForIssuerMessage() {
        return "No CRLs found for issuer";
    }
}
