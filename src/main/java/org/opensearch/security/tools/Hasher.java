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

import java.io.Console;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.hasher.PasswordHasher;
import org.opensearch.security.hasher.PasswordHasherFactory;
import org.opensearch.security.support.ConfigConstants;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(name = "hash.sh", mixinStandardHelpOptions = true, description = "Hash a password for use in internal_users.yml",
    header = {
        "",
        "@|cyan    ___                   ____                      _  |@",
        "@|cyan   / _ \\ _ __   ___ _ __ / ___|  ___  __ _ _ __ ___| |__ |@",
        "@|cyan  | | | | '_ \\ / _ \\ '_ \\\\___ \\ / _ \\/ _` | '__/ __| '_ \\|@",
        "@|cyan  | |_| | |_) |  __/ | | |___) |  __/ (_| | | | (__| | | ||@",
        "@|cyan   \\___/| .__/ \\___|_| |_|____/ \\___|\\__,_|_|  \\___|_| |_||@",
        "@|cyan        |_||@                @|bold,yellow Security Tools|@",
        ""
    })
public class Hasher implements Runnable {

    @Option(names = { "-p", "--password" }, description = "Cleartext password to hash")
    private String password;

    @Option(names = "-env", description = "Environment variable name to read password from")
    private String envVar;

    @Option(names = { "-a", "--algorithm" }, description = "Algorithm to use: BCrypt | PBKDF2 | Argon2. Default: BCrypt")
    private String algorithm;

    @Option(names = { "-r", "--rounds" }, description = "BCrypt rounds (4-31). Default: 12")
    private Integer rounds;

    @Option(names = { "-min", "--minor" }, description = "BCrypt minor version: A | B | Y. Default: Y")
    private String minor;

    @Option(names = { "-f", "--function" }, description = "PBKDF2 function: SHA1 | SHA224 | SHA256 | SHA384 | SHA512. Default: SHA256")
    private String function;

    @Option(names = { "-l", "--length" }, description = "Key length. Default: 256 (PBKDF2), 32 (Argon2)")
    private Integer length;

    @Option(names = { "-i", "--iterations" }, description = "Iterations. Default: 600000 (PBKDF2), 3 (Argon2)")
    private Integer iterations;

    @Option(names = { "-m", "--memory" }, description = "Argon2 memory in KiB. Default: 65536")
    private Integer memory;

    @Option(names = { "-par", "--parallelism" }, description = "Argon2 parallelism. Default: 1")
    private Integer parallelism;

    @Option(names = { "-t", "--type" }, description = "Argon2 type: argon2i | argon2d | argon2id. Default: argon2id")
    private String type;

    @Option(names = { "-v", "--version" }, description = "Argon2 version. Default: 19")
    private String version;

    public static void main(final String[] args) {
        int exitCode = new CommandLine(new Hasher()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public void run() {
        CommandLine.Help.Ansi ansi = CommandLine.Help.Ansi.AUTO;
        System.out.println(ansi.string(
            "@|cyan    ___                   ____                      _  |@\n"
            + "@|cyan   / _ \\ _ __   ___ _ __ / ___|  ___  __ _ _ __ ___| |__ |@\n"
            + "@|cyan  | | | | '_ \\ / _ \\ '_ \\\\___ \\ / _ \\/ _` | '__/ __| '_ \\|@\n"
            + "@|cyan  | |_| | |_) |  __/ | | |___) |  __/ (_| | | | (__| | | ||@\n"
            + "@|cyan   \\___/| .__/ \\___|_| |_|____/ \\___|\\__,_|_|  \\___|_| |_||@\n"
            + "@|cyan        |_||@                @|bold,yellow Security Tools|@\n"
        ));
        try {
            final char[] pwd = resolvePassword();
            if (algorithm != null) {
                System.out.println(hash(pwd, buildSettings()));
            } else {
                System.out.println(hash(pwd));
            }
        } catch (final Exception e) {
            System.err.println("Error: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

    private char[] resolvePassword() throws Exception {
        if (password != null) {
            return password.toCharArray();
        } else if (envVar != null) {
            final String pwd = System.getenv(envVar);
            if (pwd == null || pwd.isEmpty()) {
                throw new Exception("No environment variable '" + envVar + "' set");
            }
            return pwd.toCharArray();
        } else {
            final Console console = System.console();
            if (console == null) {
                throw new Exception("Cannot allocate a console");
            }
            return console.readPassword("[%s]", "Password:");
        }
    }

    private Settings buildSettings() throws Exception {
        Settings.Builder settings = Settings.builder();
        switch (algorithm.toLowerCase()) {
            case ConfigConstants.BCRYPT:
                settings.put(ConfigConstants.SECURITY_PASSWORD_HASHING_ALGORITHM, ConfigConstants.BCRYPT);
                if (rounds != null) settings.put(ConfigConstants.SECURITY_PASSWORD_HASHING_BCRYPT_ROUNDS, rounds);
                if (minor != null) settings.put(ConfigConstants.SECURITY_PASSWORD_HASHING_BCRYPT_MINOR, minor.toUpperCase());
                break;
            case ConfigConstants.PBKDF2:
                settings.put(ConfigConstants.SECURITY_PASSWORD_HASHING_ALGORITHM, ConfigConstants.PBKDF2);
                if (function != null) settings.put(ConfigConstants.SECURITY_PASSWORD_HASHING_PBKDF2_FUNCTION, function);
                if (length != null) settings.put(ConfigConstants.SECURITY_PASSWORD_HASHING_PBKDF2_LENGTH, length);
                if (iterations != null) settings.put(ConfigConstants.SECURITY_PASSWORD_HASHING_PBKDF2_ITERATIONS, iterations);
                break;
            case ConfigConstants.ARGON2:
                settings.put(ConfigConstants.SECURITY_PASSWORD_HASHING_ALGORITHM, ConfigConstants.ARGON2);
                if (memory != null) settings.put(ConfigConstants.SECURITY_PASSWORD_HASHING_ARGON2_MEMORY, memory);
                if (iterations != null) settings.put(ConfigConstants.SECURITY_PASSWORD_HASHING_ARGON2_ITERATIONS, iterations);
                if (parallelism != null) settings.put(ConfigConstants.SECURITY_PASSWORD_HASHING_ARGON2_PARALLELISM, parallelism);
                if (length != null) settings.put(ConfigConstants.SECURITY_PASSWORD_HASHING_ARGON2_LENGTH, length);
                if (type != null) settings.put(ConfigConstants.SECURITY_PASSWORD_HASHING_ARGON2_TYPE, type.toLowerCase());
                if (version != null) settings.put(ConfigConstants.SECURITY_PASSWORD_HASHING_ARGON2_VERSION, Integer.parseInt(version));
                break;
            default:
                throw new Exception("Unsupported hashing algorithm: " + algorithm);
        }
        return settings.build();
    }

    public static String hash(final char[] clearTextPassword) {
        return hash(clearTextPassword, Settings.EMPTY);
    }

    public static String hash(final char[] clearTextPassword, Settings settings) {
        PasswordHasher passwordHasher = PasswordHasherFactory.createPasswordHasher(settings);
        return passwordHasher.hash(clearTextPassword);
    }
}
