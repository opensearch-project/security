package com.amazon.opendistroforelasticsearch.security.support;


import org.opensearch.action.get.GetRequest;
import org.opensearch.search.fetch.subphase.FetchSourceContext;
import org.opensearch.security.user.AuthCredentials;

import java.io.Serializable;
import java.util.Map;

public class LegacyClassConverter {

    public static class User {

        public static Serializable Opensearch2ODFE(org.opensearch.security.user.User u) {

            AuthCredentials copyCred = new AuthCredentials("LegacyClassConverter");
            for (Map.Entry<String,String> entry : u.getCustomAttributesMap().entrySet()) {
                copyCred.addAttribute(entry.getKey(), entry.getValue());
            }
            return new com.amazon.opendistroforelasticsearch.security.user.User(u.getName(), u.getRoles(), copyCred);
        }

        public static Serializable ODFE2Opensearch(com.amazon.opendistroforelasticsearch.security.user.User u) {

            AuthCredentials copyCred = new AuthCredentials("LegacyClassConverter");
            for (Map.Entry<String,String> entry : u.getCustomAttributesMap().entrySet()) {
                copyCred.addAttribute(entry.getKey(), entry.getValue());
            }
            return new org.opensearch.security.user.User(u.getName(), u.getRoles(), copyCred);
        }
    }

    public static class SourceFieldsContext {

        public static Serializable Opensearch2ODFE(org.opensearch.security.support.SourceFieldsContext ctx) {

            GetRequest copyReq = new GetRequest();
            FetchSourceContext copyCtx = new FetchSourceContext(ctx.isFetchSource(), ctx.getIncludes(), ctx.getExcludes());
            copyReq.fetchSourceContext(copyCtx);
            return new com.amazon.opendistroforelasticsearch.security.support.SourceFieldsContext(copyReq);
        }

        public static Serializable ODFE2Opensearch(com.amazon.opendistroforelasticsearch.security.support.SourceFieldsContext ctx) {

            GetRequest copyReq = new GetRequest();
            FetchSourceContext copyCtx = new FetchSourceContext(ctx.isFetchSource(), ctx.getIncludes(), ctx.getExcludes());
            copyReq.fetchSourceContext(copyCtx);
            return new org.opensearch.security.support.SourceFieldsContext(copyReq);
        }
    }

}
