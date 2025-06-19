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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

import com.password4j.Argon2Function;
import com.password4j.CompressedPBKDF2Function;
import com.password4j.types.Argon2;

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

    // BCRYPT
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
    public void testWithPBKDF2Signature() {
        Hasher.main(new String[] { "-p", "password", "-a", "PBKDF2" });
        assertTrue("should return a valid PBKDF2 hash with the default configuration", out.toString().startsWith("$3$25"));
    }

    @Test
    public void testWithArgon2Signature() {
        Hasher.main(new String[] { "-p", "password", "-a", "Argon2" });
        assertTrue("should return a valid Argon2 hash with the default configuration", out.toString().startsWith("$argon2"));
    }

    // PBKDF2
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

    // ARGON2
    @Test
    public void testWithArgon2DefaultArguments() {
        Hasher.main(new String[] { "-p", "password", "-a", "Argon2" });
        Argon2Function argon2Function = Argon2Function.getInstanceFromHash(out.toString().trim());
        assertEquals("should return a valid Argon2 hash with the default value for \"memory\"", argon2Function.getMemory(), 65536);
        assertEquals("should return a valid Argon2 hash with the default value for \"iterations\"", argon2Function.getIterations(), 3);
        assertEquals("should return a valid Argon2 hash with the default value for \"parallelism\"", argon2Function.getParallelism(), 1);
        assertEquals("should return a valid Argon2 hash with the default value for \"length\"", argon2Function.getOutputLength(), 32);
        assertEquals("should return a valid Argon2 hash with the default value for \"type\"", argon2Function.getVariant(), Argon2.ID);
        assertEquals("should return a valid Argon2 hash with the default value for \"version\"", argon2Function.getVersion(), 19);
    }

    @Test
    public void testWithArgon2MemoryArgument() {
        Hasher.main(new String[] { "-p", "password", "-a", "Argon2", "-m", "47104" });
        Argon2Function argon2Function = Argon2Function.getInstanceFromHash(out.toString().trim());
        assertEquals("should return a valid Argon2 hash with the correct value for \"memory\"", argon2Function.getMemory(), 47104);
        assertEquals("should return a valid Argon2 hash with the default value for \"iterations\"", argon2Function.getIterations(), 3);
        assertEquals("should return a valid Argon2 hash with the default value for \"parallelism\"", argon2Function.getParallelism(), 1);
        assertEquals("should return a valid Argon2 hash with the default value for \"length\"", argon2Function.getOutputLength(), 32);
        assertEquals("should return a valid Argon2 hash with the default value for \"type\"", argon2Function.getVariant(), Argon2.ID);
        assertEquals("should return a valid Argon2 hash with the default value for \"version\"", argon2Function.getVersion(), 19);
        out.reset();

        Hasher.main(new String[] { "-p", "password", "-a", "Argon2", "-m", "19456" });
        argon2Function = Argon2Function.getInstanceFromHash(out.toString().trim());
        assertEquals("should return a valid Argon2 hash with the correct value for \"memory\"", argon2Function.getMemory(), 19456);
        assertEquals("should return a valid Argon2 hash with the default value for \"iterations\"", argon2Function.getIterations(), 3);
        assertEquals("should return a valid Argon2 hash with the default value for \"parallelism\"", argon2Function.getParallelism(), 1);
        assertEquals("should return a valid Argon2 hash with the default value for \"length\"", argon2Function.getOutputLength(), 32);
        assertEquals("should return a valid Argon2 hash with the default value for \"type\"", argon2Function.getVariant(), Argon2.ID);
        assertEquals("should return a valid Argon2 hash with the default value for \"version\"", argon2Function.getVersion(), 19);
    }

    @Test
    public void testWithArgon2IterationsArgument() {
        Hasher.main(new String[] { "-p", "password", "-a", "Argon2", "-i", "1" });
        Argon2Function argon2Function = Argon2Function.getInstanceFromHash(out.toString().trim());
        assertEquals("should return a valid Argon2 hash with the default value for \"memory\"", argon2Function.getMemory(), 65536);
        assertEquals("should return a valid Argon2 hash with the correct value for \"iterations\"", argon2Function.getIterations(), 1);
        assertEquals("should return a valid Argon2 hash with the default value for \"parallelism\"", argon2Function.getParallelism(), 1);
        assertEquals("should return a valid Argon2 hash with the default value for \"length\"", argon2Function.getOutputLength(), 32);
        assertEquals("should return a valid Argon2 hash with the default value for \"type\"", argon2Function.getVariant(), Argon2.ID);
        assertEquals("should return a valid Argon2 hash with the default value for \"version\"", argon2Function.getVersion(), 19);
        out.reset();

        Hasher.main(new String[] { "-p", "password", "-a", "Argon2", "-i", "5" });
        argon2Function = Argon2Function.getInstanceFromHash(out.toString().trim());
        assertEquals("should return a valid Argon2 hash with the default value for \"memory\"", argon2Function.getMemory(), 65536);
        assertEquals("should return a valid Argon2 hash with the correct value for \"iterations\"", argon2Function.getIterations(), 5);
        assertEquals("should return a valid Argon2 hash with the default value for \"parallelism\"", argon2Function.getParallelism(), 1);
        assertEquals("should return a valid Argon2 hash with the default value for \"length\"", argon2Function.getOutputLength(), 32);
        assertEquals("should return a valid Argon2 hash with the default value for \"type\"", argon2Function.getVariant(), Argon2.ID);
        assertEquals("should return a valid Argon2 hash with the default value for \"version\"", argon2Function.getVersion(), 19);
    }

    @Test
    public void testWithArgon2ParallelismArgument() {
        Hasher.main(new String[] { "-p", "password", "-a", "Argon2", "-par", "2" });
        Argon2Function argon2Function = Argon2Function.getInstanceFromHash(out.toString());
        assertEquals("should return a valid Argon2 hash with the default value for \"memory\"", argon2Function.getMemory(), 65536);
        assertEquals("should return a valid Argon2 hash with the default value for \"iterations\"", argon2Function.getIterations(), 3);
        assertEquals("should return a valid Argon2 hash with the correct value for \"parallelism\"", argon2Function.getParallelism(), 2);
        assertEquals("should return a valid Argon2 hash with the default value for \"length\"", argon2Function.getOutputLength(), 32);
        assertEquals("should return a valid Argon2 hash with the default value for \"type\"", argon2Function.getVariant(), Argon2.ID);
        assertEquals("should return a valid Argon2 hash with the default value for \"version\"", argon2Function.getVersion(), 19);
        out.reset();

        Hasher.main(new String[] { "-p", "password", "-a", "Argon2", "-par", "1" });
        argon2Function = Argon2Function.getInstanceFromHash(out.toString());
        assertEquals("should return a valid Argon2 hash with the default value for \"memory\"", argon2Function.getMemory(), 65536);
        assertEquals("should return a valid Argon2 hash with the default value for \"iterations\"", argon2Function.getIterations(), 3);
        assertEquals("should return a valid Argon2 hash with the correct value for \"parallelism\"", argon2Function.getParallelism(), 1);
        assertEquals("should return a valid Argon2 hash with the default value for \"length\"", argon2Function.getOutputLength(), 32);
        assertEquals("should return a valid Argon2 hash with the default value for \"type\"", argon2Function.getVariant(), Argon2.ID);
        assertEquals("should return a valid Argon2 hash with the default value for \"version\"", argon2Function.getVersion(), 19);
    }

    @Test
    public void testWithArgon2LengthArgument() {
        Hasher.main(new String[] { "-p", "password", "-a", "Argon2", "-l", "64" });
        Argon2Function argon2Function = Argon2Function.getInstanceFromHash(out.toString().trim());
        assertEquals("should return a valid Argon2 hash with the default value for \"memory\"", argon2Function.getMemory(), 65536);
        assertEquals("should return a valid Argon2 hash with the default value for \"iterations\"", argon2Function.getIterations(), 3);
        assertEquals("should return a valid Argon2 hash with the default value for \"parallelism\"", argon2Function.getParallelism(), 1);
        assertEquals("should return a valid Argon2 hash with the correct value for \"length\"", argon2Function.getOutputLength(), 64);
        assertEquals("should return a valid Argon2 hash with the default value for \"type\"", argon2Function.getVariant(), Argon2.ID);
        assertEquals("should return a valid Argon2 hash with the default value for \"version\"", argon2Function.getVersion(), 19);
        out.reset();

        Hasher.main(new String[] { "-p", "password", "-a", "Argon2", "-l", "12" });
        argon2Function = Argon2Function.getInstanceFromHash(out.toString().trim());
        assertEquals("should return a valid Argon2 hash with the default value for \"memory\"", argon2Function.getMemory(), 65536);
        assertEquals("should return a valid Argon2 hash with the default value for \"iterations\"", argon2Function.getIterations(), 3);
        assertEquals("should return a valid Argon2 hash with the default value for \"parallelism\"", argon2Function.getParallelism(), 1);
        assertEquals("should return a valid Argon2 hash with the correct value for \"length\"", argon2Function.getOutputLength(), 12);
        assertEquals("should return a valid Argon2 hash with the default value for \"type\"", argon2Function.getVariant(), Argon2.ID);
        assertEquals("should return a valid Argon2 hash with the default value for \"version\"", argon2Function.getVersion(), 19);
    }

    @Test
    public void testWithArgon2TypeArgument() {
        Hasher.main(new String[] { "-p", "password", "-a", "Argon2", "-t", "argon2i" });
        Argon2Function argon2Function = Argon2Function.getInstanceFromHash(out.toString().trim());
        assertEquals("should return a valid Argon2 hash with the default value for \"memory\"", argon2Function.getMemory(), 65536);
        assertEquals("should return a valid Argon2 hash with the default value for \"iterations\"", argon2Function.getIterations(), 3);
        assertEquals("should return a valid Argon2 hash with the default value for \"parallelism\"", argon2Function.getParallelism(), 1);
        assertEquals("should return a valid Argon2 hash with the default value for \"length\"", argon2Function.getOutputLength(), 32);
        assertEquals("should return a valid Argon2 hash with the correct value for \"type\"", argon2Function.getVariant(), Argon2.I);
        assertEquals("should return a valid Argon2 hash with the default value for \"version\"", argon2Function.getVersion(), 19);
        out.reset();

        Hasher.main(new String[] { "-p", "password", "-a", "Argon2", "-t", "argon2d" });
        argon2Function = Argon2Function.getInstanceFromHash(out.toString().trim());
        assertEquals("should return a valid Argon2 hash with the default value for \"memory\"", argon2Function.getMemory(), 65536);
        assertEquals("should return a valid Argon2 hash with the default value for \"iterations\"", argon2Function.getIterations(), 3);
        assertEquals("should return a valid Argon2 hash with the default value for \"parallelism\"", argon2Function.getParallelism(), 1);
        assertEquals("should return a valid Argon2 hash with the default value for \"length\"", argon2Function.getOutputLength(), 32);
        assertEquals("should return a valid Argon2 hash with the correct value for \"type\"", argon2Function.getVariant(), Argon2.D);
        assertEquals("should return a valid Argon2 hash with the default value for \"version\"", argon2Function.getVersion(), 19);
    }

    @Test
    public void testWithArgon2VersionArgument() {
        Hasher.main(new String[] { "-p", "password", "-a", "Argon2", "-v", "16" });
        Argon2Function argon2Function = Argon2Function.getInstanceFromHash(out.toString().trim());
        assertEquals("should return a valid Argon2 hash with the default value for \"memory\"", argon2Function.getMemory(), 65536);
        assertEquals("should return a valid Argon2 hash with the default value for \"iterations\"", argon2Function.getIterations(), 3);
        assertEquals("should return a valid Argon2 hash with the default value for \"parallelism\"", argon2Function.getParallelism(), 1);
        assertEquals("should return a valid Argon2 hash with the default value for \"length\"", argon2Function.getOutputLength(), 32);
        assertEquals("should return a valid Argon2 hash with the default value for \"type\"", argon2Function.getVariant(), Argon2.ID);
        assertEquals("should return a valid Argon2 hash with the correct value for \"version\"", argon2Function.getVersion(), 16);
        out.reset();

        Hasher.main(new String[] { "-p", "password", "-a", "Argon2", "-v", "19" });
        argon2Function = Argon2Function.getInstanceFromHash(out.toString().trim());
        assertEquals("should return a valid Argon2 hash with the default value for \"memory\"", argon2Function.getMemory(), 65536);
        assertEquals("should return a valid Argon2 hash with the default value for \"iterations\"", argon2Function.getIterations(), 3);
        assertEquals("should return a valid Argon2 hash with the default value for \"parallelism\"", argon2Function.getParallelism(), 1);
        assertEquals("should return a valid Argon2 hash with the default value for \"length\"", argon2Function.getOutputLength(), 32);
        assertEquals("should return a valid Argon2 hash with the default value for \"type\"", argon2Function.getVariant(), Argon2.ID);
        assertEquals("should return a valid Argon2 hash with the correct value for \"version\"", argon2Function.getVersion(), 19);
    }

    @Test
    public void testWithArgon2AllArguments() {
        Hasher.main(new String[] { "-p", "password", "-a", "Argon2", "-m", "47104", "-i", "1", "-par", "2", "-l", "64", "-t", "argon2d", "-v", "19" });
        Argon2Function argon2Function = Argon2Function.getInstanceFromHash(out.toString().trim());
        assertEquals("should return a valid Argon2 hash with the correct value for \"memory\"", argon2Function.getMemory(), 47104);
        assertEquals("should return a valid Argon2 hash with the correct value for \"iterations\"", argon2Function.getIterations(), 1);
        assertEquals("should return a valid Argon2 hash with the correct value for \"parallelism\"", argon2Function.getParallelism(), 2);
        assertEquals("should return a valid Argon2 hash with the correct value for \"length\"", argon2Function.getOutputLength(), 64);
        assertEquals("should return a valid Argon2 hash with the correct value for \"type\"", argon2Function.getVariant(), Argon2.D);
        assertEquals("should return a valid Argon2 hash with the correct value for \"version\"", argon2Function.getVersion(), 19);
    }
}
