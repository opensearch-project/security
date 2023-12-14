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

package org.opensearch.security.tools.democonfig.util;

import java.io.File;

public class DemoConfigHelperUtil {
    public static void createDirectory(String path) {
        File directory = new File(path);
        if (!directory.exists() && !directory.mkdirs()) {
            throw new RuntimeException("Failed to create directory: " + path);
        }
    }

    public static void createFile(String path) {
        try {
            File file = new File(path);
            if (!file.exists() && !file.createNewFile()) {
                throw new RuntimeException("Failed to create file: " + path);
            }
        } catch (Exception e) {
            // without this the catch, we would need to throw exception,
            // which would then require modifying caller method signature
            throw new RuntimeException("Failed to create file: " + path, e);
        }
    }

    public static void deleteDirectoryRecursive(String path) {
        File directory = new File(path);
        if (directory.exists()) {
            File[] files = directory.listFiles();
            if (files != null) {
                for (File file : files) {
                    if (file.isDirectory()) {
                        deleteDirectoryRecursive(file.getAbsolutePath());
                    } else {
                        file.delete();
                    }
                }
            }
            // Delete the empty directory after all its content is deleted
            directory.delete();
        }
    }
}
