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

package org.opensearch.security.tools;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.PrintStream;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.password4j.CompressedPBKDF2Function;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class HasherTests {
    private final ByteArrayOutputStream out = new ByteArrayOutputStream();
    private final PrintStream originalOut = System.out;
    private final InputStream originalIn = System.in;

    @Before
    public void setOutputStreams() {
        System.setOut(new PrintStream(out));
    }

    @After
    public void restoreStreams() {
        System.setOut(originalOut);
        System.setIn(originalIn);
    }

    @Test
    public void testWithDefaultArguments() {
        Hasher.main(new String[] { "-p", "password" });
        assertTrue("should return a valid BCrypt hash with the default BCrypt configuration", out.toString().startsWith("$2y$12"));
    }

    @Test
    public void testWithBCryptRoundsArgument() {
        Hasher.main(new String[] { "-p", "password", "-a", "BCrypt", "-r", "5" });
        assertTrue("should return a valid BCrypt hash with the correct value for \"rounds\"", out.toString().startsWith("$2y$05"));
        out.reset();

        Hasher.main(new String[] { "-p", "password", "-a", "BCrypt", "-r", "5" });
        assertTrue("should return a valid BCrypt hash with the correct value for \"rounds\"", out.toString().startsWith("$2y$05"));
    }

    @Test
    public void testWithBCryptMinorArgument() {
        Hasher.main(new String[] { "-p", "password", "-a", "BCrypt", "-min", "A" });
        assertTrue("should return a valid BCrypt hash with the correct value for \"minor\"", out.toString().startsWith("$2a$12"));
        out.reset();

        Hasher.main(new String[] { "-p", "password", "-a", "BCrypt", "-min", "Y" });
        assertTrue("should return a valid BCrypt hash with the correct value for \"minor\"", out.toString().startsWith("$2y$12"));
        out.reset();

        Hasher.main(new String[] { "-p", "password", "-a", "BCrypt", "-min", "B" });
        assertTrue("should return a valid BCrypt hash with the correct value for \"minor\"", out.toString().startsWith("$2b$12"));
        out.reset();
    }

    @Test
    public void testWithBCryptAllArguments() {
        Hasher.main(new String[] { "-p", "password", "-a", "BCrypt", "-min", "A", "-r", "5" });
        assertTrue("should return a valid BCrypt hash with the correct configuration", out.toString().startsWith("$2a$05"));
    }

    @Test
    public void testWithPBKDF2DefaultArguments() {
        Hasher.main(new String[] { "-p", "password", "-a", "PBKDF2" });
        CompressedPBKDF2Function pbkdf2Function = CompressedPBKDF2Function.getInstanceFromHash(out.toString());
        assertEquals("should return a valid PBKDF2 hash with the correct value for \"function\"", pbkdf2Function.getAlgorithm(), "SHA256");
        assertEquals("should return a valid PBKDF2 hash with the default value for \"iterations\"", pbkdf2Function.getIterations(), 600000);
        assertEquals("should return a valid PBKDF2 hash with the default value for \"length\"", pbkdf2Function.getLength(), 256);
    }

    @Test
    public void testWithPBKDF2FunctionArgument() {
        Hasher.main(new String[] { "-p", "password", "-a", "PBKDF2", "-f", "SHA512" });
        CompressedPBKDF2Function pbkdf2Function = CompressedPBKDF2Function.getInstanceFromHash(out.toString());
        assertEquals("should return a valid PBKDF2 hash with the correct value for \"function\"", pbkdf2Function.getAlgorithm(), "SHA512");
        assertEquals("should return a valid PBKDF2 hash with the default value for \"iterations\"", pbkdf2Function.getIterations(), 600000);
        assertEquals("should return a valid PBKDF2 hash with the default value for \"length\"", pbkdf2Function.getLength(), 256);
        out.reset();

        Hasher.main(new String[] { "-p", "password", "-a", "PBKDF2", "-f", "SHA384" });
        pbkdf2Function = CompressedPBKDF2Function.getInstanceFromHash(out.toString());
        assertEquals("should return a valid PBKDF2 hash with the correct value for \"function\"", pbkdf2Function.getAlgorithm(), "SHA384");
        assertEquals("should return a valid PBKDF2 hash with the default value for \"iterations\"", pbkdf2Function.getIterations(), 600000);
        assertEquals("should return a valid PBKDF2 hash with the default value for \"length\"", pbkdf2Function.getLength(), 256);
    }

    @Test
    public void testWithPBKDF2IterationsArgument() {
        Hasher.main(new String[] { "-p", "password", "-a", "PBKDF2", "-i", "100000" });
        CompressedPBKDF2Function pbkdf2Function = CompressedPBKDF2Function.getInstanceFromHash(out.toString());
        assertEquals("should return a valid PBKDF2 hash with the correct value for \"function\"", pbkdf2Function.getAlgorithm(), "SHA256");
        assertEquals("should return a valid PBKDF2 hash with the default value for \"iterations\"", pbkdf2Function.getIterations(), 100000);
        assertEquals("should return a valid PBKDF2 hash with the default value for \"length\"", pbkdf2Function.getLength(), 256);
        out.reset();

        Hasher.main(new String[] { "-p", "password", "-a", "PBKDF2", "-i", "200000" });
        pbkdf2Function = CompressedPBKDF2Function.getInstanceFromHash(out.toString());
        assertEquals("should return a valid PBKDF2 hash with the correct value for \"function\"", pbkdf2Function.getAlgorithm(), "SHA256");
        assertEquals("should return a valid PBKDF2 hash with the default value for \"iterations\"", pbkdf2Function.getIterations(), 200000);
        assertEquals("should return a valid PBKDF2 hash with the default value for \"length\"", pbkdf2Function.getLength(), 256);
    }

    @Test
    public void testWithPBKDF2LengthArgument() {
        Hasher.main(new String[] { "-p", "password", "-a", "PBKDF2", "-l", "400" });
        CompressedPBKDF2Function pbkdf2Function = CompressedPBKDF2Function.getInstanceFromHash(out.toString());
        assertEquals("should return a valid PBKDF2 hash with the correct value for \"function\"", pbkdf2Function.getAlgorithm(), "SHA256");
        assertEquals("should return a valid PBKDF2 hash with the default value for \"iterations\"", pbkdf2Function.getIterations(), 600000);
        assertEquals("should return a valid PBKDF2 hash with the default value for \"length\"", pbkdf2Function.getLength(), 400);
        out.reset();

        Hasher.main(new String[] { "-p", "password", "-a", "PBKDF2", "-l", "300" });
        pbkdf2Function = CompressedPBKDF2Function.getInstanceFromHash(out.toString());
        assertEquals("should return a valid PBKDF2 hash with the correct value for \"function\"", pbkdf2Function.getAlgorithm(), "SHA256");
        assertEquals("should return a valid PBKDF2 hash with the default value for \"iterations\"", pbkdf2Function.getIterations(), 600000);
        assertEquals("should return a valid PBKDF2 hash with the default value for \"length\"", pbkdf2Function.getLength(), 300);
    }

    @Test
    public void testWithPBKDF2AllArguments() {
        Hasher.main(new String[] { "-p", "password", "-a", "PBKDF2", "-l", "250", "-i", "150000", "-f", "SHA384" });
        CompressedPBKDF2Function pbkdf2Function = CompressedPBKDF2Function.getInstanceFromHash(out.toString());
        assertEquals("should return a valid PBKDF2 hash with the correct value for \"function\"", pbkdf2Function.getAlgorithm(), "SHA384");
        assertEquals("should return a valid PBKDF2 hash with the default value for \"iterations\"", pbkdf2Function.getIterations(), 150000);
        assertEquals("should return a valid PBKDF2 hash with the default value for \"length\"", pbkdf2Function.getLength(), 250);
    }
}
