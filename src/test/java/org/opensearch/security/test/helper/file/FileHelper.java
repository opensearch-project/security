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

package org.opensearch.security.test.helper.file;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.io.Streams;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

import static org.opensearch.core.xcontent.DeprecationHandler.THROW_UNSUPPORTED_OPERATION;

public class FileHelper {

    protected final static Logger log = LogManager.getLogger(FileHelper.class);

    public static KeyStore getKeystoreFromClassPath(final String fileNameFromClasspath, String password) throws Exception {
        Path path = getAbsoluteFilePathFromClassPath(fileNameFromClasspath);
        if (path == null) {
            return null;
        }

        KeyStore ks = KeyStore.getInstance("JKS");
        try (FileInputStream fin = new FileInputStream(path.toFile())) {
            ks.load(fin, password == null || password.isEmpty() ? null : password.toCharArray());
        }
        return ks;
    }

    public static Path getAbsoluteFilePathFromClassPath(final String fileNameFromClasspath) {
        File file = null;
        final URL fileUrl = FileHelper.class.getClassLoader().getResource(fileNameFromClasspath);
        if (fileUrl != null) {
            try {
                file = new File(URLDecoder.decode(fileUrl.getFile(), "UTF-8"));
            } catch (final UnsupportedEncodingException e) {
                return null;
            }

            if (file.exists() && file.canRead()) {
                return Paths.get(file.getAbsolutePath());
            } else {
                log.error("Cannot read from {}, maybe the file does not exists? ", file.getAbsolutePath());
            }

        } else {
            log.error("Failed to load {}", fileNameFromClasspath);
        }
        return null;
    }

    public static String loadFile(final String file) throws IOException {
        try (
            final StringWriter sw = new StringWriter();
            final Reader reader = new InputStreamReader(FileHelper.class.getResourceAsStream("/" + file), StandardCharsets.UTF_8)
        ) {
            Streams.copy(reader, sw);
            return sw.toString();
        }
    }

    public static BytesReference readYamlContent(final String file) {

        XContentParser parser = null;
        try {
            parser = XContentType.YAML.xContent()
                .createParser(NamedXContentRegistry.EMPTY, THROW_UNSUPPORTED_OPERATION, new StringReader(loadFile(file)));
            parser.nextToken();
            final XContentBuilder builder = XContentFactory.jsonBuilder();
            builder.copyCurrentStructure(parser);
            return BytesReference.bytes(builder);
        } catch (Exception e) {
            throw new RuntimeException(e);
        } finally {
            if (parser != null) {
                try {
                    parser.close();
                } catch (IOException e) {
                    // ignore
                }
            }
        }
    }

    public static BytesReference readYamlContentFromString(final String yaml) {

        XContentParser parser = null;
        try {
            parser = XContentType.YAML.xContent()
                .createParser(NamedXContentRegistry.EMPTY, THROW_UNSUPPORTED_OPERATION, new StringReader(yaml));
            parser.nextToken();
            final XContentBuilder builder = XContentFactory.jsonBuilder();
            builder.copyCurrentStructure(parser);
            return BytesReference.bytes(builder);
        } catch (Exception e) {
            throw new RuntimeException(e);
        } finally {
            if (parser != null) {
                try {
                    parser.close();
                } catch (IOException e) {
                    // ignore
                }
            }
        }
    }

    /**
     * Utility that copies contents of one file to another
     * @param srcFile    Source File
     * @param destFile   Destination File
     */
    public static void copyFileContents(String srcFile, String destFile) {
        try {
            final FileReader fr = new FileReader(srcFile);
            final BufferedReader br = new BufferedReader(fr);
            final FileWriter fw = new FileWriter(destFile, false);
            String s;

            while ((s = br.readLine()) != null) { // read a line
                fw.write(s); // write to output file
                fw.write(System.getProperty("line.separator"));
                fw.flush();
            }

            br.close();
            fw.close();
        } catch (IOException ignored) {}
    }
}
