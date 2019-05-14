package com.amazon.opendistroforelasticsearch.security.ssl.util;

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
import java.security.InvalidParameterException;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CRL;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertPathValidator;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
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
public class CertificateValidator
{
    
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

    private KeyStore _trustStore;
    private X509Certificate[] _trustedCert;
    private Collection<? extends CRL> _crls;

    /** Maximum certification path length (n - number of intermediate certs, -1 for unlimited) */
    private int _maxCertPathLength = -1;
    /** CRL Distribution Points (CRLDP) support */
    private boolean _enableCRLDP = false;
    /** On-Line Certificate Status Protocol (OCSP) support */
    private boolean _enableOCSP = false;
    /** Location of OCSP Responder */
    private String _ocspResponderURL;
    
    private boolean preferCrl = false;
    private boolean checkOnlyEndEntities = true;
    private Date date = null; //current date
    
    /**
     * creates an instance of the certificate validator 
     *
     * @param trustStore the truststore to use 
     * @param crls the Certificate Revocation List to use 
     */
    public CertificateValidator(KeyStore trustStore, Collection<? extends CRL> crls)
    {
        if (trustStore == null)
        {
            throw new InvalidParameterException("TrustStore must be specified for CertificateValidator.");
        }
        
        _trustStore = trustStore;
        _crls = crls;
    }
    
    public CertificateValidator(X509Certificate[] trustedCert, Collection<? extends CRL> crls)
    {
        if (trustedCert == null || trustedCert.length == 0)
        {
            throw new InvalidParameterException("trustedCert must be specified for CertificateValidator.");
        }
        
        _trustedCert = trustedCert;
        _crls = crls;
    }

    public void validate(Certificate[] certChain) throws CertificateException
    {
        try
        {
            ArrayList<X509Certificate> certList = new ArrayList<X509Certificate>();
            for (Certificate item : certChain)
            {
                if (item == null)
                    continue;
                
                if (!(item instanceof X509Certificate))
                {
                    throw new IllegalStateException("Invalid certificate type in chain");
                }

                certList.add((X509Certificate)item);
            }

            if (certList.isEmpty())
            {
                throw new IllegalStateException("Invalid certificate chain");
                
            }
    
            X509CertSelector certSelect = new X509CertSelector();
            certSelect.setCertificate(certList.get(0));
          
            CertPathBuilder certPathBuilder = CertPathBuilder.getInstance("PKIX");
            PKIXRevocationChecker revocationChecker = (PKIXRevocationChecker) certPathBuilder.getRevocationChecker();

            Set<PKIXRevocationChecker.Option> opts = new HashSet<>();
            
            if(preferCrl) {
                opts.add(PKIXRevocationChecker.Option.PREFER_CRLS);
            }
            
            //opts.add(PKIXRevocationChecker.Option.SOFT_FAIL);
            
            //opts.add(PKIXRevocationChecker.Option.NO_FALLBACK);
            
            if(checkOnlyEndEntities) {
                 opts.add(PKIXRevocationChecker.Option.ONLY_END_ENTITY);
            }
            
            revocationChecker.setOptions(opts);

            // Configure certification path builder parameters
            PKIXBuilderParameters pbParams = null;
            
            if(_trustStore != null) {
                pbParams = new PKIXBuilderParameters(_trustStore, certSelect);
            } else {
                Set<TrustAnchor> trustAnchors = new HashSet<TrustAnchor>();
                for (int i = 0; i < _trustedCert.length; i++) {
                    X509Certificate certificate = _trustedCert[i];
                    TrustAnchor trustAnchor = new TrustAnchor(certificate, null);
                    trustAnchors.add(trustAnchor);
                }

                pbParams = new PKIXBuilderParameters(trustAnchors, certSelect);
            }
            
            pbParams.addCertPathChecker(revocationChecker);
            
            pbParams.setDate(date);
            
            pbParams.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList)));
            
            // Set maximum certification path length
            pbParams.setMaxPathLength(_maxCertPathLength);
    
            // Enable revocation checking
            pbParams.setRevocationEnabled(true);
    
            // Set static Certificate Revocation List
            if (_crls != null && !_crls.isEmpty())
            {
                pbParams.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(_crls)));
            }
    
            // Enable On-Line Certificate Status Protocol (OCSP) support
            if (_enableOCSP)
            {
                Security.setProperty("ocsp.enable","true");
            }
            // Enable Certificate Revocation List Distribution Points (CRLDP) support
            if (_enableCRLDP)
            {
                System.setProperty("com.sun.security.enableCRLDP","true");
            }
    
            // Build certification path
            CertPathBuilderResult buildResult = CertPathBuilder.getInstance("PKIX").build(pbParams);               
            
            // Validate certification path
            CertPathValidator.getInstance("PKIX").validate(buildResult.getCertPath(),pbParams);
        }
        catch (GeneralSecurityException gse)
        {
            throw new CertificateException("Unable to validate certificate: " + gse.getMessage(), gse);
        }
    }

    public Collection<? extends CRL> getCrls()
    {
        return _crls;
    }

    /**
     * @return Maximum number of intermediate certificates in
     * the certification path (-1 for unlimited)
     */
    public int getMaxCertPathLength()
    {
        return _maxCertPathLength;
    }

    /* ------------------------------------------------------------ */
    /**
     * @param maxCertPathLength
     *            maximum number of intermediate certificates in
     *            the certification path (-1 for unlimited)
     */
    public void setMaxCertPathLength(int maxCertPathLength)
    {
        _maxCertPathLength = maxCertPathLength;
    }
    
    /* ------------------------------------------------------------ */
    /** 
     * @return true if CRL Distribution Points support is enabled
     */
    public boolean isEnableCRLDP()
    {
        return _enableCRLDP;
    }

    /* ------------------------------------------------------------ */
    /** Enables CRL Distribution Points Support
     * @param enableCRLDP true - turn on, false - turns off
     */
    public void setEnableCRLDP(boolean enableCRLDP)
    {
        _enableCRLDP = enableCRLDP;
    }

    /* ------------------------------------------------------------ */
    /** 
     * @return true if On-Line Certificate Status Protocol support is enabled
     */
    public boolean isEnableOCSP()
    {
        return _enableOCSP;
    }

    /* ------------------------------------------------------------ */
    /** Enables On-Line Certificate Status Protocol support
     * @param enableOCSP true - turn on, false - turn off
     */
    public void setEnableOCSP(boolean enableOCSP)
    {
        _enableOCSP = enableOCSP;
    }

    /* ------------------------------------------------------------ */
    /** 
     * @return Location of the OCSP Responder
     */
    public String getOcspResponderURL()
    {
        return _ocspResponderURL;
    }

    /* ------------------------------------------------------------ */
    /** Set the location of the OCSP Responder.
     * @param ocspResponderURL location of the OCSP Responder
     */
    public void setOcspResponderURL(String ocspResponderURL)
    {
        _ocspResponderURL = ocspResponderURL;
    }

    public Date getDate() {
        return date==null?null:(Date) date.clone();
    }

    public void setDate(Date date) {
        this.date = date==null?null:(Date) date.clone();
    }
}
