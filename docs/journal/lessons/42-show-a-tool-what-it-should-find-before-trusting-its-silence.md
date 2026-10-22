---
id: lesson-42-show-a-tool-what-it-should-find-before-trusting-its-silence
type: lesson
title: "Before trusting a discovery tool's silence, show it something it should find; an empty result is a finding about the tool until then"
date: 2026-10-21
audience: [engineer, architect, leader]
rung: enumerated
tags: [discovery, cbom]
one_line: "A scanner that reports nothing has either found nothing or cannot see — a hybrid group its TLS library lacks, a library it has no rules for, code it cannot resolve without a build — and only a known positive tells the two apart."
claims:
  - text: "Three open-source tools reported nothing where something was there: sslyze 6.2.0 against a hybrid-only TLS listener, and cdxgen 11.11.0 and sonar-cryptography 1.6.1 against two federal repositories with cryptographic call sites."
    provenance: "measured 2026-10-21; note 15"
reuse: [runbook, customer-question]
---

# Before trusting a discovery tool's silence, show it something it should find; an empty result is a finding about the tool until then

## The rule

Run every discovery tool first against a target holding what it is meant to
find — a planted estate, a labelled repository — and treat an empty or partial
result elsewhere as unknown until it has passed that test.

## Why

A tool's output is bounded by what it can speak and what it has rules for,
and it rarely says where that boundary is. A TLS scanner whose library predates
ML-KEM cannot offer the hybrid group, so a listener that requires it looks like
no TLS at all. A source scanner covers named libraries; code that hashes with
the standard library or signs tokens with another package is outside it, and
the report says "no cryptography assets were detected". A Java analyser that
resolves types from compiled classes finds nothing in source alone. Each of
these is silence that reads like a clean result.

## When it applies

Choosing a scanner, comparing vendors, and reading any inventory a tool
produced on an estate no one has labelled. It matters most for post-quantum
work, where the newest algorithms are the ones older tools cannot see.

## How to apply it

- Score the tool against a planted estate with an answer key (here,
  `pqch import … --key agency/answer-key.yaml`), including decoys it should
  not report.
- For code, use a repository with labelled call sites in the libraries the
  target actually uses, and check the tool's library coverage against them.
- Record the tool's version and image digest with every result; coverage
  changes between releases.
