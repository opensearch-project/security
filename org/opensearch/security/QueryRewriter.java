import org.opensearch.security.Masking;
import org.opensearch.security.SearchSourceBuilder;

public class QueryRewriter {

    public SearchSourceBuilder rewrite(SearchSourceBuilder source) {
        // Check if field masking is enabled
        if (Masking.isEnabled()) {
            // Check if the query contains any masked fields
            if (source.containsMaskedFields()) {
                // Rewrite the query to exclude masked fields
                return rewriteQueryToExcludeMaskedFields(source);
            }
        }
        return source;
    }

    private SearchSourceBuilder rewriteQueryToExcludeMaskedFields(SearchSourceBuilder source) {
        // Create a new search source builder
        SearchSourceBuilder rewrittenSource = new SearchSourceBuilder();

        // Iterate over the fields in the original query
        for (String field : source.getFields()) {
            // Check if the field is masked
            if (!Masking.isFieldMasked(field)) {
                // Add the field to the rewritten query
                rewrittenSource.addField(field);
            }
        }

        return rewrittenSource;
    }
}