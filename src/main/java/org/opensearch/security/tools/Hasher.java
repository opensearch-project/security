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

import org.apache.commons.cli.*;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.hasher.PasswordHasher;
import org.opensearch.security.hasher.PasswordHasherFactory;
import org.opensearch.security.support.ConfigConstants;

public class Hasher {

    private static final String PASSWORD_OPTION = "p";
    private static final String ENV_OPTION = "env";
    private static final String ALGORITHM_OPTION = "a";
    private static final String ROUNDS_OPTION = "r";
    private static final String FUNCTION_OPTION = "f";
    private static final String LENGTH_OPTION = "l";
    private static final String ITERATIONS_OPTION = "i";
    private static final String MINOR_OPTION = "min";
    private static final String HELP_OPTION = "h";

    public static void main(final String[] args) {
        final HelpFormatter formatter = new HelpFormatter();
        formatter.setOptionComparator(null);
        Options options = buildOptions();
        final CommandLineParser parser = new DefaultParser();
        try {
            final CommandLine line = parser.parse(options, args);
            final char[] password;

            if (line.hasOption(HELP_OPTION)) {
                formatter.printHelp("hash.sh", options, true);
                System.exit(0);
            }

            if (line.hasOption(PASSWORD_OPTION)) {
                password = line.getOptionValue(PASSWORD_OPTION).toCharArray();
            } else if (line.hasOption(ENV_OPTION)) {
                final String pwd = System.getenv(line.getOptionValue(ENV_OPTION));
                if (pwd == null || pwd.isEmpty()) {
                    throw new Exception("No environment variable '" + line.getOptionValue(ENV_OPTION) + "' set");
                }
                password = pwd.toCharArray();
            } else {
                final Console console = System.console();
                if (console == null) {
                    throw new Exception("Cannot allocate a console");
                }
                password = console.readPassword("[%s]", "Password:");
            }
            if (line.hasOption(ALGORITHM_OPTION)) {
                String algorithm = line.getOptionValue(ALGORITHM_OPTION);
                Settings settings;
                switch (algorithm.toLowerCase()) {
                    case ConfigConstants.BCRYPT:
                        settings = getBCryptSettings(line);
                        break;
                    case ConfigConstants.PBKDF2:
                        settings = getPBKDF2Settings(line);
                        break;
                    default:
                        throw new Exception("Unsupported hashing algorithm: " + algorithm);
                }
                System.out.println(hash(password, settings));
            } else {
                System.out.println(hash(password));
            }

        } catch (final Exception exp) {
            System.err.println("Parsing failed.  Reason: " + exp.getMessage());
            formatter.printHelp("hash.sh", options, true);
            System.exit(-1);
        }
    }

    public static String hash(final char[] clearTextPassword) {
        return hash(clearTextPassword, Settings.EMPTY);
    }

    public static String hash(final char[] clearTextPassword, Settings settings) {
        PasswordHasher passwordHasher = PasswordHasherFactory.createPasswordHasher(settings);
        return passwordHasher.hash(clearTextPassword);
    }

    private static Settings getBCryptSettings(CommandLine line) throws ParseException {
        Settings.Builder settings = Settings.builder();
        settings.put(ConfigConstants.SECURITY_PASSWORD_HASHING_ALGORITHM, ConfigConstants.BCRYPT);
        if (line.hasOption(ROUNDS_OPTION)) {
            settings.put(
                ConfigConstants.SECURITY_PASSWORD_HASHING_BCRYPT_ROUNDS,
                ((Number) line.getParsedOptionValue(ROUNDS_OPTION)).intValue()
            );
        }
        if (line.hasOption(MINOR_OPTION)) {
            settings.put(ConfigConstants.SECURITY_PASSWORD_HASHING_BCRYPT_MINOR, line.getOptionValue(MINOR_OPTION).toUpperCase());
        }
        return settings.build();
    }

    private static Settings getPBKDF2Settings(CommandLine line) throws ParseException {
        Settings.Builder settings = Settings.builder();
        settings.put(ConfigConstants.SECURITY_PASSWORD_HASHING_ALGORITHM, ConfigConstants.PBKDF2);
        if (line.hasOption(FUNCTION_OPTION)) {
            settings.put(ConfigConstants.SECURITY_PASSWORD_HASHING_PBKDF2_FUNCTION, line.getOptionValue(FUNCTION_OPTION));
        }
        if (line.hasOption(LENGTH_OPTION)) {
            settings.put(
                ConfigConstants.SECURITY_PASSWORD_HASHING_PBKDF2_LENGTH,
                ((Number) line.getParsedOptionValue(LENGTH_OPTION)).intValue()
            );
        }
        if (line.hasOption(ITERATIONS_OPTION)) {
            settings.put(
                ConfigConstants.SECURITY_PASSWORD_HASHING_PBKDF2_ITERATIONS,
                ((Number) line.getParsedOptionValue(ITERATIONS_OPTION)).intValue()
            );
        }
        return settings.build();
    }

    private static Options buildOptions() {
        final Options options = new Options();
        options.addOption(Option.builder(HELP_OPTION).longOpt("help").desc("Display the help information").argName("help").build());
        options.addOption(
            Option.builder(PASSWORD_OPTION).longOpt("password").argName("password").hasArg().desc("Cleartext password to hash").build()
        );
        options.addOption(
            Option.builder(ENV_OPTION)
                .argName("Environment variable name")
                .hasArg()
                .desc("Environment variable name to read password from")
                .build()
        );
        options.addOption(
            Option.builder(ALGORITHM_OPTION)
                .longOpt("algorithm")
                .argName("hashing algorithm")
                .hasArg()
                .desc("Algorithm to use for password hashing. Valid values are: BCrypt | PBKDF2. Default: BCrypt")
                .build()
        );
        options.addOption(
            Option.builder(ROUNDS_OPTION)
                .longOpt("rounds")
                .desc("Number of rounds to use in logarithmic form. Valid values are: 4 to 31. Default: 12")
                .hasArg()
                .argName("rounds (BCrypt)")
                .type(Number.class)
                .build()
        );
        options.addOption(
            Option.builder(MINOR_OPTION)
                .longOpt("minor")
                .desc("Version of BCrypt algorithm to use. Valid values are: A | B | Y. Default: Y")
                .hasArg()
                .argName("minor (BCrypt)")
                .build()
        );
        options.addOption(
            Option.builder(LENGTH_OPTION)
                .longOpt("length")
                .desc("Desired length of the final derived key. Default: 256")
                .hasArg()
                .argName("length (PBKDF2)")
                .type(Number.class)
                .build()
        );
        options.addOption(
            Option.builder(FUNCTION_OPTION)
                .longOpt("function")
                .desc(
                    "Pseudo-random function applied to the password. Valid values are SHA1 | SHA224 | SHA256 | SHA384 | SHA512. Default: SHA256"
                )
                .hasArg()
                .argName("function (PBDKF2)")
                .build()
        );
        options.addOption(
            Option.builder(ITERATIONS_OPTION)
                .longOpt("iterations")
                .desc("Number of times the pseudo-random function is applied to the password. Default: 600000")
                .hasArg()
                .argName("iterations (PBKDF2)")
                .type(Number.class)
                .build()
        );
        return options;
    }
}
