---
id: lesson-74-size-a-drawing-from-the-screen-not-a-constant
type: lesson
title: "A drawing that must fit one screen takes its height from that screen, and shares it among its rows by what each row needs; a constant cap leaves room unused while the rows collide"
date: 2026-11-13
audience: [engineer, architect]
rung: all
tags: [demo, layout, qa]
one_line: "The stage's opening drew three bands into a height capped by a stylesheet constant: on an 883 px screen it took 443 px, left 250 px empty under itself, and spread eight services 10 px apart in 12 px type. Sized from the screen and divided by what each band's rows need, the same drawing takes 600 px on that screen and nothing overlaps; four screen sizes were rendered to check."
claims:
  - text: "At 1813 × 883 the opening beat's drawing was 443 px tall, from a stylesheet rule that took the viewport less 440 px and capped the result at 780, and divided it 29 · 31 · 36 per cent among the sheet, the chain and the plan: eight services 10 px apart, eight plan lanes 14 px each under 17 px step boxes, and 250 px of the screen empty below."
    provenance: "measured 2026-11-13 in headless Chromium at 1813 × 883, the snapshot copy of the stage served from this tree; the same crowding in the owner's captures of the live stage and the published copy"
  - text: "Sized from the screen (the room under the heading, less the sentence and the beat bar, never under 560 px) and divided by need (the sheet takes its rows' height, the rest splits 45 · 55 between the chain and the plan), the drawing is 600 px on the same screen without the site header and 560 px under it; services sit 15 px apart, lanes 19 px, and the whole beat still fits the screen at 1813 × 883, 1440 × 900 and 1280 × 720."
    provenance: "measured 2026-11-13 in headless Chromium at those sizes, dark scheme, snapshot stills at band 3 and the live beat after its 20 s of animation; the UI tests pass"
reuse: [talk]
---

# A drawing that must fit one screen takes its height from that screen, and shares it among its rows by what each row needs; a constant cap leaves room unused while the rows collide

## The rule

A figure built to fill one screen without scrolling is sized by the script
that draws it, from the room the screen actually leaves it: the viewport,
less what sits above the figure and what must stay visible under it. The
figure then gives each of its rows the height that row's content needs, and
splits only the remainder by proportion. A stylesheet constant can neither
see what is above the figure nor know how many rows are in it, so it is
always wrong in one direction: too tall and the page scrolls, too short and
the labels collide while the screen stays half empty.

<figure class="sketch" markdown>
![Two drawings of the same 883 px screen. Left, capped by a constant: a heading, then three bands in 443 px, the sheet 129 px, the chain's eight services 10 px apart, the plan's eight lanes 14 px each, then 250 px marked empty above the sentence and the beat bar; a red ring round the empty room with the note that 250 px went unused while the labels collided. Right, sized from the screen: the same three bands in 600 px, the sheet at its rows' height of 180 px, eight services 15 px apart, eight lanes 19 px each, the sentence under them and the bar at the foot.](../img/sketches/74-size-the-drawing-from-the-screen.svg)
<figcaption>The same screen twice: a constant cap leaves a quarter of it empty while the rows collide; measured from the screen, the same drawing has room.</figcaption>
</figure>

## Why

The opening beat's drawing was given a height in the stylesheet: the viewport
less 440 px, kept between 440 and 780. The 440 was a guess at the heading
above and the sentence and bar below, made at one window size and never
measured again. Above the drawing the heading grew to a 46 px title and two
lines of outcome; below it the sentence took two lines; and the drawing's
three bands were cut by fixed fractions that gave the chain, with its eight
service labels and nine listener labels, less than a third of whatever was
left. On the owner's screen the drawing came out at 443 px: eight services in
80 px, step boxes taller than the lanes they sat in, listener labels written
over one another, and a quarter of the screen blank underneath. The owner's
two captures, the live stage and the published copy, showed the same
crowding, because both run the same script against the same rule.

The script already measured the drawing's width from its box. It now
measures its top too, takes the viewport height less that top and less the
fixed room for the sentence and the bar, and draws into the result. Inside,
the sheet band is given the height its rows need (six rows, 20 px each, plus
its headings), and the chain and the plan share what remains, the plan a
little more because its step boxes are taller than a service label. Listener
labels are pushed apart to a 12 px minimum down their column, and the plan's
stray dots and its count line share a footer row instead of the last lane.
The heading shrank to 38 px and the sentence to 15.5 px, which is what the
room above and below the drawing actually needs.

## When it applies

Any figure meant to stand on one screen without scrolling: a demonstration
beat, a dashboard panel, a kiosk page, a slide drawn by script. It applies
whenever the figure's content is a list whose length the data decides
(services, lanes, rows) and the room around it is set by text whose length
the copy decides.

## How to apply it

1. Let the script measure: the figure's top from its bounding box, the
   viewport's height, and a fixed allowance for what must stay visible under
   the figure. Give the figure that height, with a floor under which the page
   may scroll rather than crush its rows.
2. Give each row-bearing band the height its rows need, from the data's
   count and the type size; split only the remainder by proportion.
3. Where labels ride on data positions, push them apart to a minimum pitch
   in a pass after layout; move the label, never the mark.
4. Keep counts and stray marks in their own row; a label placed at the
   figure's last pixel will meet whatever else was placed there.
5. Render at the sizes people use (here 1813 × 883 with and without the site
   header, 1440 × 900, 1280 × 720) and look, before shipping: the collisions
   were visible in any screenshot and in no test.

## Where the claim stops

One figure, one script, four sizes rendered. The floor of 560 px means a
short window (under about 760 px with the site header) scrolls; the figure
does not yet drop a band or its labels for small screens. The published copy
takes the change only when it is rebuilt and published.
