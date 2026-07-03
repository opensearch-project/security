import org.opensearch.security.QueryRewriter;
import org.opensearch.security.SearchSourceBuilder;

public class SearchRequest {

    public SearchSourceBuilder source;

    public SearchRequest(String index) {
        source = new SearchSourceBuilder();
    }

    public void setSource(SearchSourceBuilder source) {
        this.source = source;
    }

    public SearchSourceBuilder getSource() {
        return source;
    }

    public void setSource(SearchSourceBuilder source, QueryRewriter rewriter) {
        this.source = rewriter.rewrite(source);
    }
}