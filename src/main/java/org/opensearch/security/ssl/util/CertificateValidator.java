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

package org.opensearch.security.ssl.util;

//
//  ========================================================================
//  Copyright (c) 1995-2017 Mort Bay Consulting Pty. Ltd.
//  ------------------------------------------------------------------------
//  All rights reserved. This program and the accompanying materials
//  are made available under the terms of the Eclipse Public License v1.0
//  and Apache License v2.0 which accompanies this distribution.
//
//      The Eclipse Public License is available at
//      http://www.eclipse.org/legal/epl-v10.html
//
//      The Apache License v2.0 is available at
//      http://www.opensource.org/licenses/apache2.0.php
//
//  You may elect to redistribute this code under either of these licenses.
//  ========================================================================
//

import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.cert.CRL;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertPathValidator;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Convenience class to handle validation of certificates, aliases and keystores
 *
 * Allows specifying Certificate Revocation List (CRL), as well as enabling
 * CRL Distribution Points Protocol (CRLDP) certificate extension support,
 * and also enabling On-Line Certificate Status Protocol (OCSP) support.
 *
 * IMPORTANT: at least one of the above mechanisms *MUST* be configured and
 * operational, otherwise certificate validation *WILL FAIL* unconditionally.
 */
public class CertificateValidator {

    boolean isPreferCrl() {
        return preferCrl;
    }

    void setPreferCrl(boolean preferCrl) {
        this.preferCrl = preferCrl;
    }

    boolean isCheckOnlyEndEntities() {
        return checkOnlyEndEntities;
    }

    void setCheckOnlyEndEntities(boolean checkOnlyEndEntities) {
        this.checkOnlyEndEntities = checkOnlyEndEntities;
    }

    private final Set<TrustAnchor> _trustAnchors;
    private Collection<? extends CRL> _crls;

    /** Maximum certification path length (n - number of intermediate certs, -1 for unlimited) */
    private int _maxCertPathLength = -1;
    /** CRL Distribution Points (CRLDP) support */
    private boolean _enableCRLDP = false;
    /** On-Line Certificate Status Protocol (OCSP) support */
    private boolean _enableOCSP = false;

    private boolean preferCrl = false;
    private boolean checkOnlyEndEntities = true;
    private Date date = null; // current date

    public CertificateValidator(Set<TrustAnchor> trustAnchors, Collection<? extends CRL> crls) {
        _trustAnchors = trustAnchors;
        _crls = crls;
    }

    public void validate(X509Certificate[] certChain) throws GeneralSecurityException {
        X509CertSelector certSelect = new X509CertSelector();
        certSelect.setCertificate(certChain[0]);

        CertStore chainStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(List.of(certChain)));

        CertPathBuilder certPathBuilder = CertPathBuilder.getInstance("PKIX", "SUN");
        PKIXRevocationChecker revocationChecker = (PKIXRevocationChecker) certPathBuilder.getRevocationChecker();
        PKIXBuilderParameters params = new PKIXBuilderParameters(_trustAnchors, certSelect);
        params.setDate(date);
        params.setMaxPathLength(_maxCertPathLength);
        params.addCertStore(chainStore);
        // Keeping revocation disabled here ensures CertPathBuilder.build() throws only
        // CertPathBuilderException for structural failures (unknown CA, broken chain, etc.)
        // and never conflates those with revocation failures.
        params.setRevocationEnabled(false);
        CertPathBuilderResult buildResult = certPathBuilder.build(params);

        Set<PKIXRevocationChecker.Option> opts = new HashSet<>();
        if (preferCrl) {
            opts.add(PKIXRevocationChecker.Option.PREFER_CRLS);
        }
        if (checkOnlyEndEntities) {
            opts.add(PKIXRevocationChecker.Option.ONLY_END_ENTITY);
        }
        revocationChecker.setOptions(opts);

        params.setRevocationEnabled(true);
        params.addCertPathChecker(revocationChecker);

        if (_crls != null && !_crls.isEmpty()) {
            params.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(_crls)));
        }

        // Enable On-Line Certificate Status Protocol (OCSP) support
        if (_enableOCSP) {
            Security.setProperty("ocsp.enable", "true");
        }
        // Enable Certificate Revocation List Distribution Points (CRLDP) support
        if (_enableCRLDP) {
            System.setProperty("com.sun.security.enableCRLDP", "true");
        }

        CertPathValidator.getInstance("PKIX", "SUN").validate(buildResult.getCertPath(), params);
    }

    public Collection<? extends CRL> getCrls() {
        return _crls;
    }

    /* ------------------------------------------------------------ */
    /**
     * @return true if CRL Distribution Points support is enabled
     */
    public boolean isEnableCRLDP() {
        return _enableCRLDP;
    }

    /* ------------------------------------------------------------ */
    /** Enables CRL Distribution Points Support
     * @param enableCRLDP true - turn on, false - turns off
     */
    public void setEnableCRLDP(boolean enableCRLDP) {
        _enableCRLDP = enableCRLDP;
    }

    /* ------------------------------------------------------------ */
    /**
     * @return true if On-Line Certificate Status Protocol support is enabled
     */
    public boolean isEnableOCSP() {
        return _enableOCSP;
    }

    /* ------------------------------------------------------------ */
    /** Enables On-Line Certificate Status Protocol support
     * @param enableOCSP true - turn on, false - turn off
     */
    public void setEnableOCSP(boolean enableOCSP) {
        _enableOCSP = enableOCSP;
    }

    public Date getDate() {
        return date == null ? null : (Date) date.clone();
    }

    public void setDate(Date date) {
        this.date = date == null ? null : (Date) date.clone();
    }
}
