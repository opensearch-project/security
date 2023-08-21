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

package org.opensearch.test.framework.testplugins.dummy;

import com.google.common.collect.ImmutableList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.test.framework.testplugins.AbstractRestHandler;

import java.util.List;

import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class LegacyRestHandler extends AbstractRestHandler {

    private static final List<Route> routes = addRoutesPrefix(
        ImmutableList.of(new Route(POST, "/dummy"), new Route(GET, "/dummy")),
        "/_plugins/_dummy"
    );

    private final Logger log = LogManager.getLogger(this.getClass());

    public LegacyRestHandler() {
        super();
    }

    @Override
    public List<Route> routes() {
        return routes;
    }

    @Override
    public String getName() {
        return "Dummy Rest Action";
    }
}
