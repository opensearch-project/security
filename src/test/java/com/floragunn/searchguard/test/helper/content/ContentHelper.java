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

package com.floragunn.searchguard.test.helper.content;

public class ContentHelper {

	/*public static XContentBuilder parseJsonContent(final String jsonContent) {
		try {
			return readXContent(new StringReader(jsonContent), XContentType.YAML);
		} catch (IOException e) {
			return null;
		}
	}
	
	public static XContentBuilder readXContent(final Reader reader, final XContentType xContentType) throws IOException {
		XContentParser parser = null;
		try {
			parser = XContentFactory.xContent(xContentType).createParser(reader);
			parser.nextToken();
			final XContentBuilder builder = XContentFactory.jsonBuilder();
			builder.copyCurrentStructure(parser);
			return builder;
		} finally {
			if (parser != null) {
				parser.close();
			}
		}
	}*/
}
