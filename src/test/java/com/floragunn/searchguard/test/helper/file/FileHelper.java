/*
 * Copyright 2016 by floragunn UG (haftungsbeschränkt) - All rights reserved
 * 
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed here is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * 
 * This software is free of charge for non-commercial and academic use. 
 * For commercial use in a production environment you have to obtain a license 
 * from https://floragunn.com
 * 
 */

package com.floragunn.searchguard.test.helper.file;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;

import org.apache.commons.io.IOUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.XContentType;

import com.floragunn.searchguard.SearchGuardPlugin;

public class FileHelper {

	protected final static Logger log = LogManager.getLogger(FileHelper.class);

	public static KeyStore getKeystoreFromClassPath(final String fileNameFromClasspath, String password) throws Exception {
	    File file = getAbsoluteFilePathFromClassPath(fileNameFromClasspath);
	    if(file==null) {
	        return null;
	    }
	    
	    KeyStore ks = KeyStore.getInstance("JKS");
	    try (FileInputStream fin = new FileInputStream(file)) {
	        ks.load(fin, password==null||password.isEmpty()?null:password.toCharArray());
	    }
	    return ks;
	}
	
	public static File getAbsoluteFilePathFromClassPath(final String fileNameFromClasspath) {
		File file = null;
		final URL fileUrl = SearchGuardPlugin.class.getClassLoader().getResource(fileNameFromClasspath);
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

	public static final String loadFile(final String file) throws IOException {
		final StringWriter sw = new StringWriter();
		IOUtils.copy(FileHelper.class.getResourceAsStream("/" + file), sw, StandardCharsets.UTF_8);
		return sw.toString();
	}
	
    public static BytesReference readYamlContent(final String file) {
        
        XContentParser parser = null;
        try {
            parser = XContentFactory.xContent(XContentType.YAML).createParser(NamedXContentRegistry.EMPTY, new StringReader(loadFile(file)));
            parser.nextToken();
            final XContentBuilder builder = XContentFactory.jsonBuilder();
            builder.copyCurrentStructure(parser);
            return builder.bytes();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        finally {
            if (parser != null) {
                parser.close();
            }
        }
	}
}
