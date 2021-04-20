/*
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

package com.amazon.opendistroforelasticsearch.security.ssl;

import java.io.File;
import java.io.FileInputStream;
import java.security.cert.CRL;
import java.security.cert.CertPathBuilderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateRevokedException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.ExceptionsHelper;
import org.junit.Assert;
import org.junit.Test;

import com.amazon.opendistroforelasticsearch.security.ssl.util.CertificateValidator;
import com.amazon.opendistroforelasticsearch.security.ssl.util.ExceptionUtils;
import com.amazon.opendistroforelasticsearch.security.test.helper.file.FileHelper;

public class CertificateValidatorTest {
    
    public static final Date CRL_DATE = new Date(1525546426000L);
    protected final Logger log = LogManager.getLogger(this.getClass());
    
    @Test
    public void testStaticCRL() throws Exception {
        
        File staticCrl = FileHelper.getAbsoluteFilePathFromClassPath("ssl/crl/revoked.crl").toFile();
        Collection<? extends CRL> crls = null;
        try(FileInputStream crlin = new FileInputStream(staticCrl)) {
            crls = CertificateFactory.getInstance("X.509").generateCRLs(crlin);
        }
        
        Assert.assertEquals(crls.size(), 1);
        
        //trust chain incl intermediate certificates (root + intermediates)
        Collection<? extends Certificate> rootCas;
        final File trustedCas = FileHelper.getAbsoluteFilePathFromClassPath("ssl/chain-ca.pem").toFile();
        try(FileInputStream trin = new FileInputStream(trustedCas)) {
            rootCas =  (Collection<? extends Certificate>) CertificateFactory.getInstance("X.509").generateCertificates(trin);
        }
        
        Assert.assertEquals(rootCas.size(), 2);

        //certificate chain to validate (client cert + intermediates but without root)
        Collection<? extends Certificate> certsToValidate;
        final File certs = FileHelper.getAbsoluteFilePathFromClassPath("ssl/crl/revoked.crt.pem").toFile();
        try(FileInputStream trin = new FileInputStream(certs)) {
            certsToValidate =  (Collection<? extends Certificate>) CertificateFactory.getInstance("X.509").generateCertificates(trin);
        }
        
        Assert.assertEquals(certsToValidate.size(), 2);
        
        CertificateValidator validator = new CertificateValidator(rootCas.toArray(new X509Certificate[0]), crls);
        validator.setDate(CRL_DATE);
        try {
            validator.validate(certsToValidate.toArray(new X509Certificate[0]));
            Assert.fail();
        } catch (CertificateException e) {
            Assert.assertTrue(ExceptionUtils.getRootCause(e) instanceof CertificateRevokedException);
        }
    }
    
    @Test
    public void testStaticCRLOk() throws Exception {
        
        File staticCrl = FileHelper.getAbsoluteFilePathFromClassPath("ssl/crl/revoked.crl").toFile();
        Collection<? extends CRL> crls = null;
        try(FileInputStream crlin = new FileInputStream(staticCrl)) {
            crls = CertificateFactory.getInstance("X.509").generateCRLs(crlin);
        }
        
        Assert.assertEquals(crls.size(), 1);
        
        //trust chain incl intermediate certificates (root + intermediates)
        Collection<? extends Certificate> rootCas;
        final File trustedCas = FileHelper.getAbsoluteFilePathFromClassPath("ssl/chain-ca.pem").toFile();
        try(FileInputStream trin = new FileInputStream(trustedCas)) {
            rootCas =  (Collection<? extends Certificate>) CertificateFactory.getInstance("X.509").generateCertificates(trin);
        }
        
        Assert.assertEquals(rootCas.size(), 2);

        //certificate chain to validate (client cert + intermediates but without root)
        Collection<? extends Certificate> certsToValidate;
        final File certs = FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0.crt.pem").toFile();
        try(FileInputStream trin = new FileInputStream(certs)) {
            certsToValidate =  (Collection<? extends Certificate>) CertificateFactory.getInstance("X.509").generateCertificates(trin);
        }
        
        Assert.assertEquals(certsToValidate.size(), 3);
        
        CertificateValidator validator = new CertificateValidator(rootCas.toArray(new X509Certificate[0]), crls);
        validator.setDate(CRL_DATE);
        try {
            validator.validate(certsToValidate.toArray(new X509Certificate[0]));
        } catch (CertificateException e) {
            Assert.fail(ExceptionsHelper.stackTrace(ExceptionUtils.getRootCause(e)));
        }
    }
    
    @Test
    public void testNoValidationPossible() throws Exception {

        //trust chain incl intermediate certificates (root + intermediates)
        Collection<? extends Certificate> rootCas;
        final File trustedCas = FileHelper.getAbsoluteFilePathFromClassPath("ssl/chain-ca.pem").toFile();
        try(FileInputStream trin = new FileInputStream(trustedCas)) {
            rootCas =  (Collection<? extends Certificate>) CertificateFactory.getInstance("X.509").generateCertificates(trin);
        }
        
        Assert.assertEquals(rootCas.size(), 2);

        //certificate chain to validate (client cert + intermediates but without root)
        Collection<? extends Certificate> certsToValidate;
        final File certs = FileHelper.getAbsoluteFilePathFromClassPath("ssl/crl/revoked.crt.pem").toFile();
        try(FileInputStream trin = new FileInputStream(certs)) {
            certsToValidate =  (Collection<? extends Certificate>) CertificateFactory.getInstance("X.509").generateCertificates(trin);
        }
        
        Assert.assertEquals(certsToValidate.size(), 2);

        CertificateValidator validator = new CertificateValidator(rootCas.toArray(new X509Certificate[0]), Collections.emptyList());
        validator.setDate(CRL_DATE);
        try {
            validator.validate(certsToValidate.toArray(new X509Certificate[0]));
            Assert.fail();
        } catch (CertificateException e) {
            Assert.assertTrue(e.getCause() instanceof CertPathBuilderException);
            Assert.assertTrue(e.getCause().getMessage().contains("unable to find valid certification path to requested target"));
        }
    }
    
    @Test
    public void testCRLDP() throws Exception {

        //trust chain incl intermediate certificates (root + intermediates)
        Collection<? extends Certificate> rootCas;
        final File trustedCas = FileHelper.getAbsoluteFilePathFromClassPath("ssl/root-ca.pem").toFile();
        try(FileInputStream trin = new FileInputStream(trustedCas)) {
            rootCas =  (Collection<? extends Certificate>) CertificateFactory.getInstance("X.509").generateCertificates(trin);
        }
        
        Assert.assertEquals(rootCas.size(), 1);

        //certificate chain to validate (client cert + intermediates but without root)
        Collection<? extends Certificate> certsToValidate;
        final File certs = FileHelper.getAbsoluteFilePathFromClassPath("ssl/crl/revoked.crt.pem").toFile();
        //final File certs = getAbsoluteFilePathFromClassPath("ssl/node-0.crt.pem");
        try(FileInputStream trin = new FileInputStream(certs)) {
            certsToValidate =  (Collection<? extends Certificate>) CertificateFactory.getInstance("X.509").generateCertificates(trin);
        }
        
        Assert.assertEquals(certsToValidate.size(), 2);
        
        CertificateValidator validator = new CertificateValidator(rootCas.toArray(new X509Certificate[0]), Collections.emptyList());
        validator.setEnableCRLDP(true);
        validator.setEnableOCSP(true);
        validator.setDate(CRL_DATE);
        try {
            validator.validate(certsToValidate.toArray(new X509Certificate[0]));
            Assert.fail();
        } catch (CertificateException e) {
            Assert.assertTrue(ExceptionUtils.getRootCause(e) instanceof CertificateRevokedException);
        }
    }
}
