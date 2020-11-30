package org.elasticsearch.search.aggregations.bucket.terms;

import org.apache.lucene.util.BytesRef;
import org.elasticsearch.search.DocValueFormat;
import org.elasticsearch.search.aggregations.BucketOrder;

public class StringTermsGetter {
    private StringTermsGetter() {
    }

    public static BucketOrder getReduceOrder(StringTerms stringTerms) {
        return stringTerms.reduceOrder;
    }

    public static BytesRef getTerm(StringTerms.Bucket bucket) {
        return bucket.termBytes;
    }

    public static DocValueFormat getDocValueFormat(StringTerms.Bucket bucket) {
        return bucket.format;
    }
}
