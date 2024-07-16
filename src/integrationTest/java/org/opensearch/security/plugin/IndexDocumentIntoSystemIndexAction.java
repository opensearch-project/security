package org.opensearch.security.plugin;

import org.opensearch.action.ActionType;

public class IndexDocumentIntoSystemIndexAction extends ActionType<IndexDocumentIntoSystemIndexResponse> {
    public static final IndexDocumentIntoSystemIndexAction INSTANCE = new IndexDocumentIntoSystemIndexAction();
    public static final String NAME = "mock:systemindex/index";

    private IndexDocumentIntoSystemIndexAction() {
        super(NAME, IndexDocumentIntoSystemIndexResponse::new);
    }
}
