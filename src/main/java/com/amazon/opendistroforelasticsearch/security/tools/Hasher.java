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

package com.amazon.opendistroforelasticsearch.security.tools;

import java.io.Console;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;

public class Hasher {

    public static void main(final String[] args) {

        final Options options = new Options();
        final HelpFormatter formatter = new HelpFormatter();
        options.addOption(Option.builder("p").argName("password").hasArg().desc("Cleartext password to hash").build());
        options.addOption(Option.builder("env").argName("name environment variable").hasArg().desc("name environment variable to read password from").build());

        final CommandLineParser parser = new DefaultParser();
        try {
            final CommandLine line = parser.parse(options, args);
            
            if(line.hasOption("p")) {
                System.out.println(hash(line.getOptionValue("p").toCharArray()));
            } else if(line.hasOption("env")) {
                final String pwd = System.getenv(line.getOptionValue("env"));
                if(pwd == null || pwd.isEmpty()) {
                    throw new Exception("No environment variable '"+line.getOptionValue("env")+"' set");
                }
                System.out.println(hash(pwd.toCharArray()));
            } else {
                final Console console = System.console();
                if(console == null) {
                    throw new Exception("Cannot allocate a console");
                }
                final char[] passwd = console.readPassword("[%s]", "Password:");
                System.out.println(hash(passwd));
            }  
        } catch (final Exception exp) {
            System.err.println("Parsing failed.  Reason: " + exp.getMessage());
            formatter.printHelp("hasher.sh", options, true);
            System.exit(-1);
        }
    }

    public static String hash(final char[] clearTextPassword) {
        final byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        final String hash = OpenBSDBCrypt.generate((Objects.requireNonNull(clearTextPassword)), salt, 12);
        Arrays.fill(salt, (byte)0);
        Arrays.fill(clearTextPassword, '\0');
        return hash;
    }
}
