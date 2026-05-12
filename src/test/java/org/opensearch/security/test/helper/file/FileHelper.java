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
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.util.List;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.CryptoServicesRegistrar;

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

    public static final Map<String, List<String>> TYPE_TO_EXTENSION_MAP = Map.of(
        "JKS",
        List.of(".jks", ".ks"),
        "PKCS12",
        List.of(".p12", ".pkcs12", ".pfx"),
        "BCFKS", // Bouncy Castle FIPS Keystore
        List.of(".bcfks")
    );

    public static String inferStoreType(Path filePath) {
        return inferStoreType(filePath.getFileName().toString());
    }

    /**
     * Make a best guess about the "type" (see {@link KeyStore#getType()}) of the keystore file located at the given {@code Path}.
     * This method only references the <em>file name</em> of the keystore, it does not look at its contents.
     */
    public static String inferStoreType(String filePath) {
        return TYPE_TO_EXTENSION_MAP.entrySet()
            .stream()
            .filter(entry -> entry.getValue().stream().anyMatch(filePath::endsWith))
            .map(Map.Entry::getKey)
            .findFirst()
            .orElseThrow(() -> new IllegalArgumentException("Unknown keystore type for file path: " + filePath));
    }

    public record TypedStore(Path path, String type) {
    }

    public static KeyStore getKeystoreFromClassPath(final String baseName, String password) throws Exception {
        TypedStore store = resolveStore(baseName);
        KeyStore ks = KeyStore.getInstance(store.type());
        try (FileInputStream fin = new FileInputStream(store.path().toFile())) {
            ks.load(fin, password == null || password.isEmpty() ? null : password.toCharArray());
        }
        return ks;
    }

    /**
     * Resolves a keystore/truststore classpath resource by base name (without extension),
     * returning both the path and the inferred keystore type.
     * <p>
     * The format is chosen based on the runtime environment:
     * <ul>
     *   <li>FIPS approved-only mode ({@link CryptoServicesRegistrar#isInApprovedOnlyMode()}) →
     *       {@code .bcfks} / {@code "BCFKS"}</li>
     *   <li>Non-FIPS → {@code .jks} / {@code "JKS"} if a JKS variant exists on the classpath,
     *       otherwise {@code .p12} / {@code "PKCS12"}</li>
     * </ul>
     *
     * @param baseName classpath-relative base name without extension, e.g. {@code "ssl/truststore"}
     * @return a {@link TypedStore} holding the absolute path and the store type string
     * @throws IllegalStateException if no matching file is found on the classpath
     */
    public static TypedStore resolveStore(final String baseName) {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode()) {
            return new TypedStore(getAbsoluteFilePathFromClassPath(baseName + ".bcfks"), "BCFKS");
        }
        if (classpathResourceExists(baseName + ".jks")) {
            return new TypedStore(getAbsoluteFilePathFromClassPath(baseName + ".jks"), "JKS");
        }
        return new TypedStore(getAbsoluteFilePathFromClassPath(baseName + ".p12"), "PKCS12");
    }

    public static TypedStore resolveStore(final Path dir, final String baseName, final String nonFipsExtension) {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode()) {
            return new TypedStore(dir.resolve(baseName + ".bcfks"), "BCFKS");
        }
        Path path = dir.resolve(baseName + nonFipsExtension);
        return new TypedStore(path, inferStoreType(path));
    }

    public static boolean classpathResourceExists(final String name) {
        return FileHelper.class.getClassLoader().getResource(name) != null;
    }

    public static Path getAbsoluteFilePathFromClassPath(final String fileNameFromClasspath) {
        final URL fileUrl = FileHelper.class.getClassLoader().getResource(fileNameFromClasspath);
        if (fileUrl != null) {
            File file = new File(URLDecoder.decode(fileUrl.getFile(), StandardCharsets.UTF_8));
            if (file.exists() && file.canRead()) {
                return Paths.get(file.getAbsolutePath());
            }
            throw new IllegalStateException("Classpath resource exists but cannot be read: " + file.getAbsolutePath());
        }
        throw new IllegalStateException("Classpath resource not found: " + fileNameFromClasspath);
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
