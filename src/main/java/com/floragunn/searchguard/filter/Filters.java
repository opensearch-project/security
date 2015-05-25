/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package com.floragunn.searchguard.filter;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import com.floragunn.searchguard.filter.Filter.Type;

/*
 * THIS CLASS IS NOT USED YET
 * TODO Will be used in the future to store filter configuration in an index
{
    "filters":[
        {
            "type":"actionrequest",
            "name":"readonly",
            "allowed_actions":[
                "indices:data/read/*",
                "*monitor*"
            ],
            "forbidden_actions":[
                "cluster:*",
                "indices:admin*"
            ]
        },
        {
            "type":"dls",
            "name":"docsonly",
            "dls_type":"term",
            "field":"_type",
            "value":"doc",
            "negate":false
        }
    ]
}
 *
 */

public class Filters implements Serializable {

    private Set<Filter> filter;

    public final Set<Filter> getFilter() {
        return filter;
    }

    public final void setFilter(final Set<Filter> filter) {
        this.filter = filter;
    }

    public final Set<Filter> getFilter(final Type type) {
        final Set<Filter> retVal = new HashSet<Filter>();
        for (final Iterator iterator = filter.iterator(); iterator.hasNext();) {
            final Filter f = (Filter) iterator.next();
            if (f.getType() == type) {
                retVal.add(f);
            }
        }

        return retVal;
    }

}
