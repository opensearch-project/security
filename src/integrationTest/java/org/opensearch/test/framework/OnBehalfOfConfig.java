/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */
package org.opensearch.test.framework;

import java.io.IOException;

import org.apache.commons.lang3.StringUtils;

import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;

public class OnBehalfOfConfig implements ToXContentObject {
    private Boolean oboEnabled;
    private String signing_key;
    private String encryption_key;

    public OnBehalfOfConfig oboEnabled(Boolean oboEnabled) {
        this.oboEnabled = oboEnabled;
        return this;
    }

    public OnBehalfOfConfig signing_key(String signing_key) {
        this.signing_key = signing_key;
        return this;
    }

    public OnBehalfOfConfig encryption_key(String encryption_key) {
        this.encryption_key = encryption_key;
        return this;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder xContentBuilder, ToXContent.Params params) throws IOException {
        xContentBuilder.startObject();
        if (oboEnabled || oboEnabled == null) {
            xContentBuilder.field("on_behalf_of_enabled", oboEnabled);
        }
        xContentBuilder.field("signing_key", signing_key);
        if (StringUtils.isNoneBlank(encryption_key)) {
            xContentBuilder.field("encryption_key", encryption_key);
        }
        xContentBuilder.endObject();
        return xContentBuilder;
    }
}
