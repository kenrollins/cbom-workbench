---
id: lesson-60-before-a-component-goes-in-a-picture-find-its-call-site
type: lesson
title: "Before a component goes in an architecture picture, find the line of code that calls it; a stack drawn from what the box has installed claims parts the system never uses"
date: 2026-11-05
audience: [architect, engineer, leader]
rung: all
tags: [agility]
one_line: "An architecture drawing is a claim about what the system does, so each box in it needs a call site, and each path through it needs a code path; drawing what is installed beside the system, or what a reference design would use, puts parts in front of an audience that a single question exposes."
claims:
  - text: "The demonstration's architecture beat showed a Milvus vector store and a NeMo Retriever rerank NIM, and a question path through Milvus answered by the deliberate tier; no module in src/pqch imports a vector-database client or calls a reranker, Ask the CBOM ranks passages by a cosine over a cached index in the application and then walks two hops up the CBOM's dependencies by rule, and the ask-cbom role is bound to the fast tier without thinking."
    provenance: "observed 2026-11-05: grep over src/pqch for milvus and rerank (only the stage's drawing matched); src/pqch/ask/__init__.py, retrieve(); kit/inference.promax.yaml roles"
reuse: [talk, runbook]
---

# Before a component goes in an architecture picture, find the line of code that calls it

## The rule

Draw a component in an architecture picture only when you can point to the code that calls it, and
draw a path through the picture only when a request follows that path in the code. Write the call
site next to each box in the drawing's source. A component that is installed on the machine but not
called stays out, or is drawn apart and labelled as available.

## Why

A picture is believed more readily than a sentence and checked less often. A box tends to arrive
because it belongs to the platform, sits on the machine, or appears in a reference design. Milvus and
the rerank NIM were on the demonstration box, part of its RAG stack, and a retrieval-augmented system
"usually" has both. Retrieval here is an embedding call, a cosine over a few hundred cached vectors
inside the application, and a rule that follows the CBOM's dependencies. That is enough at this size,
and it is easier to explain. The picture claimed more than the system does. One question from a
technical judge ("what is in your vector store?") would have exposed it, and the honest answer would
have cost the drawing its credibility.

The same holds for paths. The question journey was drawn ending at the deliberate tier after Ask had
moved to the fast tier without thinking by measurement (lesson 58). A drawing is not updated when a
role moves unless the role's binding is what the drawing reads.

## When it applies

Every architecture picture shown to someone who may act on it: a demonstration, a design review, a
proposal. It does not apply to a picture labelled as a target or reference design, as long as the
label is in the picture and not only in the speaker's words.

## How to apply it

Before showing the picture, search for each box's call site:

```sh
for c in milvus rerank embed vllm signer runner; do printf '%-8s ' $c; grep -rli "$c" src/pqch --include=*.py | head -1 | grep . || echo NONE; done
```

A box with no call site comes out. A path is checked against the role bindings in the tier map. The
field notes' drawing of the stack (`tools/draw.py`, `sketch_arch_five_layers`) states the check in
its docstring, with the date it was made.
