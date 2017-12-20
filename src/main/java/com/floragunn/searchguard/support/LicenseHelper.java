/*
 * Copyright 2015-2017 floragunn GmbH
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
 * Copied from https://github.com/bcgit/bc-java/blob/master/pg/src/test/java/org/bouncycastle/openpgp/test/PGPClearSignedSignatureTest.java
 *
 * Copyright (c) 2000-2017 The Legion of the Bouncy Castle Inc. (http://www.bouncycastle.org)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software 
 * and associated documentation files (the "Software"), to deal in the Software without restriction, 
 * including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all copies or substantial
 * portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 */

package com.floragunn.searchguard.support;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.SignatureException;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;

import com.google.common.io.BaseEncoding;

public class LicenseHelper {

    /**
     * Validate pgp signature of license
     * 
     * @param licenseText base64 encoded pgp signed license
     * @return The plain license in json (if validation is successful)
     * @throws PGPException if validation fails
     */
    public static String validateLicense(String licenseText) throws PGPException {
        
    	licenseText = licenseText.trim().replaceAll("\\r|\\n", "");
        licenseText = licenseText.replace("---- SCHNIPP (Armored PGP signed JSON as base64) ----","");
        licenseText = licenseText.replace("---- SCHNAPP ----","");
        
        try {
            final byte[] armoredPgp = BaseEncoding.base64().decode(licenseText);

            final ArmoredInputStream in = new ArmoredInputStream(new ByteArrayInputStream(armoredPgp));

            //
            // read the input, making sure we ignore the last newline.
            //
            // https://github.com/bcgit/bc-java/blob/master/pg/src/test/java/org/bouncycastle/openpgp/test/PGPClearSignedSignatureTest.java

            final ByteArrayOutputStream bout = new ByteArrayOutputStream();
            int ch;

            while ((ch = in.read()) >= 0 && in.isClearText()) {
                bout.write((byte) ch);
            }

            final KeyFingerPrintCalculator c = new BcKeyFingerprintCalculator();

            final PGPObjectFactory factory = new PGPObjectFactory(in, c);
            final PGPSignatureList sigL = (PGPSignatureList) factory.nextObject();
            final PGPPublicKeyRingCollection pgpRings = new PGPPublicKeyRingCollection(new ArmoredInputStream(
                    LicenseHelper.class.getResourceAsStream("/KEYS")), c);

            if (sigL == null || pgpRings == null || sigL.size() == 0 || pgpRings.size() == 0) {
                throw new PGPException("Cannot find license signature");
            }

            final PGPSignature sig = sigL.get(0);
            final PGPPublicKey publicKey = pgpRings.getPublicKey(sig.getKeyID());

            if (publicKey == null || sig == null) {
                throw new PGPException("license signature key mismatch");
            }

            sig.init(new BcPGPContentVerifierBuilderProvider(), publicKey);

            final ByteArrayOutputStream lineOut = new ByteArrayOutputStream();
            final InputStream sigIn = new ByteArrayInputStream(bout.toByteArray());
            int lookAhead = readInputLine(lineOut, sigIn);

            processLine(sig, lineOut.toByteArray());

            if (lookAhead != -1) {
                do {
                    lookAhead = readInputLine(lineOut, lookAhead, sigIn);

                    sig.update((byte) '\r');
                    sig.update((byte) '\n');

                    processLine(sig, lineOut.toByteArray());
                } while (lookAhead != -1);
            }

            if (!sig.verify()) {
                throw new PGPException("Invalid license signature");
            }

            return bout.toString();
        } catch (final Exception e) {
            throw new PGPException(e.toString(), e);
        }
    }

    private static int readInputLine(final ByteArrayOutputStream bOut, final InputStream fIn) throws IOException {
        bOut.reset();

        int lookAhead = -1;
        int ch;

        while ((ch = fIn.read()) >= 0) {
            bOut.write(ch);
            if (ch == '\r' || ch == '\n') {
                lookAhead = readPassedEOL(bOut, ch, fIn);
                break;
            }
        }

        return lookAhead;
    }

    private static int readInputLine(final ByteArrayOutputStream bOut, int lookAhead, final InputStream fIn) throws IOException {
        bOut.reset();

        int ch = lookAhead;

        do {
            bOut.write(ch);
            if (ch == '\r' || ch == '\n') {
                lookAhead = readPassedEOL(bOut, ch, fIn);
                break;
            }
        } while ((ch = fIn.read()) >= 0);

        return lookAhead;
    }

    private static int readPassedEOL(final ByteArrayOutputStream bOut, final int lastCh, final InputStream fIn) throws IOException {
        int lookAhead = fIn.read();

        if (lastCh == '\r' && lookAhead == '\n') {
            bOut.write(lookAhead);
            lookAhead = fIn.read();
        }

        return lookAhead;
    }

    private static void processLine(final PGPSignature sig, final byte[] line) throws SignatureException, IOException {
        final int length = getLengthWithoutWhiteSpace(line);
        if (length > 0) {
            sig.update(line, 0, length);
        }
    }

    private static int getLengthWithoutWhiteSpace(final byte[] line) {
        int end = line.length - 1;

        while (end >= 0 && isWhiteSpace(line[end])) {
            end--;
        }

        return end + 1;
    }

    private static boolean isWhiteSpace(final byte b) {
        return b == '\r' || b == '\n' || b == '\t' || b == ' ';
    }
}
