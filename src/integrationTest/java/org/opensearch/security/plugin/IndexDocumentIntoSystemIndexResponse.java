package org.opensearch.security.plugin;

import java.io.IOException;

import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;

public class IndexDocumentIntoSystemIndexResponse extends AcknowledgedResponse implements ToXContentObject {

    private String plugin;

    public IndexDocumentIntoSystemIndexResponse(boolean status, String plugin) {
        super(status);
        this.plugin = plugin;
    }

    public IndexDocumentIntoSystemIndexResponse(StreamInput in) throws IOException {
        super(in);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeString(plugin);
    }

    @Override
    public void addCustomFields(XContentBuilder builder, ToXContent.Params params) throws IOException {
        super.addCustomFields(builder, params);
        builder.field("plugin", plugin);
    }
}
