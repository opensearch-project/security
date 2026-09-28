# CHANGELOG

As of the 3.6 release [the CHANGELOG is no longer used](https://github.com/opensearch-project/OpenSearch/issues/21071) to generate release notes.
[Use this PR search](https://github.com/opensearch-project/security/pulls?q=sort%3Amerged-desc+is%3Apr+-label%3Askip-changelog+is%3Amerged+base%3Amain+) to browse unreleased changes.

Release notes are now auto-generated from PR metadata at release time using an LLM-based pipeline in [opensearch-build](https://github.com/opensearch-project/opensearch-build).
See the [release notes script](https://github.com/opensearch-project/opensearch-build/blob/main/src/release_notes_workflow/release_notes.py) and [LLM prompt](https://github.com/opensearch-project/opensearch-build/blob/main/src/release_notes_workflow/release_notes_prompt.txt) for details.
