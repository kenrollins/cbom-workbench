---
id: lesson-61-give-an-animated-presentation-a-snapshot-mode
type: lesson
title: "Give an animated presentation a snapshot mode that draws each frame's final state at once, and photograph every frame before presenting it"
date: 2026-11-05
audience: [engineer]
rung: all
tags: [agility]
one_line: "Animated pages hide their defects in motion and in timing, and a headless browser photographs the first frame, not the last; a mode that skips delays and draws the end state lets a machine take a still of every beat, and the stills show text, overflow and errors that a run-through glides past."
claims:
  - text: "Stills of the demonstration's eight beats in snapshot mode showed three defects a live run-through had not: a card reading '[object Object]' where a verdict's status belonged, an elapsed time of '×Infinity' measured from the wrong event, and a closing beat drawn half-way because an exception in one panel stopped the rest."
    provenance: "observed 2026-11-04 on the demo GB10: Firefox headless screenshots of /demo?snap=1#<beat> at 1920x1080; fixed in commit 35768d6"
reuse: [runbook]
---

# Give an animated presentation a snapshot mode, and photograph every frame

## The rule

A page that presents in beats, with counters that climb, panels that fade in and graphs that settle,
needs a mode in which every beat draws its final state at once. Use that mode to take a still of
every beat at the resolution it will be shown at, then read each still before the presentation.

## Why

A run-through watches motion, and the eye forgives what passes quickly: a placeholder that is
replaced a second later, a number that is wrong only while it is counting, a panel that never
arrives because the one before it threw an exception. A headless browser's screenshot is taken when
the page has loaded, which is the first frame of each animation, not the last. So without a snapshot
mode neither a person nor a machine sees the state the audience will be left looking at.

The snapshot mode does three things: the data is inlined in the page, so nothing waits on the
network; every delay is zero and every transition is finished; and a page error is written into the
page, so the still shows it. Each beat then renders the same way every time, and a defect is in the
picture. The stills here caught an object printed as `[object Object]`, an elapsed time of
`×Infinity` measured from an event the change did not have, and a beat drawn half-way.

## When it applies

Any presentation built as a web page with animation or live data: a demonstration, a dashboard shown
on a screen, a walkthrough. It does not replace a run-through at full speed, which tests timing and
pace; it tests what is drawn.

## How to apply it

The demonstration takes `?snap=1`. Each beat is a fragment:

```sh
firefox --headless --no-remote --profile <scratch>/prof --window-size=1920,1080 \
  --screenshot beat.png "http://127.0.0.1:8080/demo?snap=1#scan"
```

A fresh profile renders the light colour scheme. To shoot the dark scheme, put
`user_pref("ui.systemUsesDarkTheme", 1);` in the profile's `user.js`. Inside the page, the snapshot
flag zeroes the delay helper, sets every counter and gauge to its end value, and catches each panel's
errors separately, so one failure cannot hide the rest of the beat.
