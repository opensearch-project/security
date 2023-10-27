- [Using this Document](#using-this-document)
	- [Feature Description](#feature-description-)
	- [Architecture Diagram](#architecture-diagram)
		- [API Diagram](#api-diagram)
	- [Documenting your Feature](#documenting-your-feature)
	- [Security Reviews](#security-reviews)

## Document Checklist
- [ ] Architecture diagram created 
- [ ] API diagram created
- [ ] Documentation pull request opened
- [ ] Security review opened if required

<!--
# Using this Document

This document provides an easy-to-use template to help you get started building your own design document for OpenSearch features.

To use this document you should:

1. Copy and paste the contents of the document to a new file <YOUR_FEATURE>.md or to the body of a GitHub comment.
2. Fill out the remainder of this document.

**Please do not overwrite this document.**

-->

## Feature Description

<!--
_Please provide a **brief** description of what feature you are introducing and what it does. This should include information about the scope of the change and and its technical aspects. It should not reiterate the GitHub description._

For example: This feature creates a token with properties x, y, & z, it will have Rest APIs: POST /_security/foo/token { ... }. It will add functionality in class files AFactory, BSingleton, and CInstance.
-->

This document outlines a new feature <YOUR_FEATURE>.

<YOUR_FEATURE> is...

## Architecture Diagram



<!--_Some features are best explained using architecture diagrams. In particular, Mermaid diagrams are supported by GitHub and preferred. You can find examples of Mermaid diagrams in the [ARCHITECTURE.md](./ARCHITECTURE.md) file._-->

<!--Here is a generic graph diagram you can modify:-->

```mermaid
graph TD
    subgraph Subgraph
        subgraph Subsubgraph1
            l1[Label 1]
            l2[Label 2]
        end
        subgraph Subsubgraph2
            l3(Label 3)
            l4[Label 4]
        end
        subgraph Subsubgraph3
           l5(Label 5)
           l6[Label 6]
        end

        l1 -- Line 1 --> l3
        l2 -- Line 2 --> l4
        l3 -- Line 3 --> l5
    end
```

<!--Similarly, this is a sample sequence diagram:-->

```mermaid
sequenceDiagram
	title Sample Sequence
	autonumber

    A->>B: Request 1
    B->>C: Request 1 Received
    C->>D: Handle Request 
    D->>C: Do Something
    C-->>B: Allow/Deny request
    C->>E: Update Audit Log
    D-->>B: Result
    B->>A: Response
```

<!--There are several other types of diagrams also supported by Mermaid.-->


### API Diagram

<!--If your change introduces new API routes, please provide a diagram of the changes.-->

<!--The sequence diagram is recommended for this purpose:-->

```mermaid
sequenceDiagram
	title Sample Sequence
	autonumber

    A->>B: Request 1
    B->>C: Request 1 Received
    C->>D: Handle Request 
    D->>C: Do Something
    C-->>B: Allow/Deny request
    C->>E: Update Audit Log
    D-->>B: Result
    B->>A: Response
```

## Documenting your Feature

<!--Whenever you are making a large change, you should make sure you have created the appropriate updates to the documentation website.

Please use this section as a reminder to submit a pull request to the documentation repository with the details of your change.

If you do not complete this step, your pull request may not be merged.

Please link your documentation pull request here when it is complete and check the box below.-->

## Security Reviews

Certain changes require advanced security reviews by parties which depend on OpenSearch.

As part of this process, we request that the following decision tree is used to determine in which cases an advanced security review is required.

In cases where an advanced review is required, additional time is needed to merge pull requests. In these cases, the earlier pertinent information is provided the better.

Please denote whether a review is expected to be required.

```mermaid
graph TD
  A[Is it a new feature or a feature update?] -->|New Feature| B[Does the feature handle sensitive data?]
  A -->|Feature Update| C[Does the update change security-critical components?]
  B -->|Yes| D[Create a security review]
  B -->|No| E[Do a basic security assessment]
  C -->|Yes| D[Create a security review]
  C -->|No| E[Do a basic security assessment]
  E -->|Security concern found?| D[Create a security review]
```
