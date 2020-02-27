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

package com.amazon.opendistroforelasticsearch.security.ssl;

import java.io.File;
import java.io.FileInputStream;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLDecoder;
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
import org.elasticsearch.ExceptionsHelper;
import org.junit.Assert;
import org.junit.Test;

import com.amazon.opendistroforelasticsearch.security.ssl.util.CertificateValidator;
import com.amazon.opendistroforelasticsearch.security.ssl.util.ExceptionUtils;

public class CertificateValidatorTest {
    
    public static final Date CRL_DATE = new Date(1525546426000L);
    protected final Logger log = LogManager.getLogger(this.getClass());
    
    @Test
    public void testStaticCRL() throws Exception {
        
        File staticCrl = getAbsoluteFilePathFromClassPath("crl/revoked.crl");
        Collection<? extends CRL> crls = null;
        try(FileInputStream crlin = new FileInputStream(staticCrl)) {
            crls = CertificateFactory.getInstance("X.509").generateCRLs(crlin);
        }
        
        Assert.assertEquals(crls.size(), 1);
        
        //trust chain incl intermediate certificates (root + intermediates)
        Collection<? extends Certificate> rootCas;
        final File trustedCas = getAbsoluteFilePathFromClassPath("chain-ca.pem");
        try(FileInputStream trin = new FileInputStream(trustedCas)) {
            rootCas =  (Collection<? extends Certificate>) CertificateFactory.getInstance("X.509").generateCertificates(trin);
        }
        
        Assert.assertEquals(rootCas.size(), 2);

        //certificate chain to validate (client cert + intermediates but without root)
        Collection<? extends Certificate> certsToValidate;
        final File certs = getAbsoluteFilePathFromClassPath("crl/revoked.crt.pem");
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
        
        File staticCrl = getAbsoluteFilePathFromClassPath("crl/revoked.crl");
        Collection<? extends CRL> crls = null;
        try(FileInputStream crlin = new FileInputStream(staticCrl)) {
            crls = CertificateFactory.getInstance("X.509").generateCRLs(crlin);
        }
        
        Assert.assertEquals(crls.size(), 1);
        
        //trust chain incl intermediate certificates (root + intermediates)
        Collection<? extends Certificate> rootCas;
        final File trustedCas = getAbsoluteFilePathFromClassPath("chain-ca.pem");
        try(FileInputStream trin = new FileInputStream(trustedCas)) {
            rootCas =  (Collection<? extends Certificate>) CertificateFactory.getInstance("X.509").generateCertificates(trin);
        }
        
        Assert.assertEquals(rootCas.size(), 2);

        //certificate chain to validate (client cert + intermediates but without root)
        Collection<? extends Certificate> certsToValidate;
        final File certs = getAbsoluteFilePathFromClassPath("node-0.crt.pem");
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
        final File trustedCas = getAbsoluteFilePathFromClassPath("chain-ca.pem");
        try(FileInputStream trin = new FileInputStream(trustedCas)) {
            rootCas =  (Collection<? extends Certificate>) CertificateFactory.getInstance("X.509").generateCertificates(trin);
        }
        
        Assert.assertEquals(rootCas.size(), 2);

        //certificate chain to validate (client cert + intermediates but without root)
        Collection<? extends Certificate> certsToValidate;
        final File certs = getAbsoluteFilePathFromClassPath("crl/revoked.crt.pem");
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
        final File trustedCas = getAbsoluteFilePathFromClassPath("root-ca.pem");
        try(FileInputStream trin = new FileInputStream(trustedCas)) {
            rootCas =  (Collection<? extends Certificate>) CertificateFactory.getInstance("X.509").generateCertificates(trin);
        }
        
        Assert.assertEquals(rootCas.size(), 1);

        //certificate chain to validate (client cert + intermediates but without root)
        Collection<? extends Certificate> certsToValidate;
        final File certs = getAbsoluteFilePathFromClassPath("crl/revoked.crt.pem");
        //final File certs = getAbsoluteFilePathFromClassPath("node-0.crt.pem");
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

    public File getAbsoluteFilePathFromClassPath(final String fileNameFromClasspath) {
        File file = null;
        final URL fileUrl = AbstractUnitTest.class.getClassLoader().getResource(fileNameFromClasspath);
        if (fileUrl != null) {
            try {
                file = new File(URLDecoder.decode(fileUrl.getFile(), "UTF-8"));
            } catch (final UnsupportedEncodingException e) {
                return null;
            }

            if (file.exists() && file.canRead()) {
                return file;
            } else {
                log.error("Cannot read from {}, maybe the file does not exists? ", file.getAbsolutePath());
            }

        } else {
            log.error("Failed to load " + fileNameFromClasspath);
        }
        return null;
    }
}
