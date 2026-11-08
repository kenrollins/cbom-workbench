# Lessons

One rule per lesson: the rule, why it holds, when it applies, how to apply it.
Read `../STYLE.md` before writing one. Lessons are standing guidance, written
in the present tense.

Filename: `NN-short-slug.md`. Never renumber.

A lesson is written when something measured in the project yields a rule that
would hold in another project. It states the rule and the mechanism, not the
day it was learned.

## Written

| # | Rule | Rung |
|---|---|---|
| 01 | When verifying that a post-quantum key exchange is required, offer every classical group | agile |
| 02 | Give an isolated Docker network no host address, and test for it | all |
| 03 | Carry a registry in an offline bundle; `docker save` and `docker load` do not preserve digest references | all |
| 04 | Believe an identity header only on a connection from the proxy that sets it | managed |
| 05 | Score an inventory for what it invents, and put a decoy in every layer it is scored on | enumerated |
| 06 | Record which container a scan reached, and join evidence only when it is the one you think it is | structured |
| 07 | Take the key that verifies a signed log from somewhere other than the log | all |
| 08 | Identify a key in an inventory by the hash of its public key, not by where it was found | structured |
| 09 | Time a file scanner on the bare base image first; symlinks, not size, can set its cost | enumerated |
| 10 | Count a key-exchange group as accepted only when it is the one negotiated | enumerated |
| 11 | Prove a passive-monitoring script fires on traffic you generated before reading its silence as absence | enumerated |
| 12 | Check cited evidence against the question it was meant to answer, then derive the conclusion again | agile |
| 13 | To bound when a logged event happened, sign the log just before it and just after | all |
| 14 | Do not switch branches under a running container that bind-mounts the tree; make the health check read the files | all |
| 15 | Hash every blob in an offline bundle's registry before serving it, and keep the checksum file's own hash somewhere else | all |
| 16 | Count a change as applied only when the service answers, and put the old configuration back when it does not | agile |
| 17 | In a bundle build, always rebuild what must match the source and record the commit; reuse only what must not change | all |
| 18 | Observe what a service accepts with nothing configured before planning its migration | enumerated |
| 19 | Label a cause only after changing it and watching the effect go | all |
| 20 | Before reading a configuration, know which occurrence of a setting wins in that software | structured |
| 21 | Set a floor per role before comparing two models, and repeat every call before believing it | all |
| 22 | Deploy from a checkout nobody edits | all |
| 24 | A hardware label in a config is a claim; record what served the call | all |
| 25 | Size the scanner network's address range to the parallelism, and record a job that never started as its own failure | enumerated |
| 26 | Name the reasoning setting beside the model in every measurement and binding | all |
| 27 | Before keying a TLS listener, probe each kind of key exchange on its own: named groups, finite-field DHE, RSA key transport | enumerated |
| 28 | Read a certificate's CA flag together with its key usage; a self-signed server certificate is usually marked CA:TRUE | structured |
| 29 | Give a listener that carries TLS behind a protocol upgrade its own scan profile; a plain TLS scan of its port is silent, not negative | enumerated |
| 31 | Confirm every cause an answer key names by changing it, including the ones written as annotations | all |
| 32 | Ask the protocol stack's runtime what it will negotiate before calling a migration blocked, or not blocked, by its supplier | managed |
| 33 | Read a validated module's certificate for the algorithm you need, and check that the module is active, before calling a system validated | managed |
| 34 | Score the retrieval step on its own before scoring a model's answer over it | all |
| 35 | Compare two inventories by the identity of each observation and by what it says, leaving out references to the records behind it | managed |
| 36 | When verifying that a listener requires post-quantum key establishment, probe TLS 1.2 on its own; a classical-only TLS 1.3 client is refused, not downgraded | agile |
| 37 | When a probe claims a handshake the enumerating witness does not find, call the verdict inconclusive and say why | agile |
| 38 | Before citing or redrawing a standard, read its status; cite the current revision by its own identifier | all |
| 39 | Every label in a diagram of what a system does is a claim; fill it from the record and check each | all |
| 40 | Draw a cryptographic inventory in columns along its dependency chain, not as a force-directed graph | structured |
| 41 | Before approving a change that requires post-quantum key establishment, probe each kind of client against a copy with the change | agile |
| 42 | Before trusting a discovery tool's silence, show it something it should find | enumerated |
| 43 | Report a change's time from approval to proof beside its time from policy to proof | agile |
| 44 | Publish a curated export, checked for leaks, not the working repository | all |
| 45 | Score an inventory against a key that knows about changes: an item a verified change removed is remediated, not missed | agile |
| 46 | After publishing a repository, read its own checks | all |
| 47 | Before a demonstration, open the published page in a browser at each width it will be seen at, and read its network log | all |
| 48 | Write each CBOM fact in CycloneDX's own field; where the standard has none, name the property as the tools you feed read it | structured |
| 49 | Before binding a role to an engine on a new machine, check the four things the engine decides for itself: its GPU profile, its window, its memory share, its model id | all |
| 50 | When a bundle keeps an image from one build to the next, key it to a hash of its build context, never to its name | all |
| 51 | Where a protocol upgrade can be refused, ask for it once and record the answer before scanning what it would carry | enumerated |
| 52 | An inventory read as an ordinary user must list every path it could not open, and the plan must carry the privileged read | enumerated |
| 53 | An offline install carries the build backend with the wheelhouse and installs outside the lock file; nothing in the runbook calls the package manager's run command | all |
| 54 | When a box already serves the engines on its loopback, join their containers to the kit's bridge under the kit's names instead of starting them again | all |
| 55 | A reply cap on a thinking tier is a thinking budget: set it from the measured tokens of the role's hardest items, and record a cut-off as an empty reply | all |
| 56 | A signer's first signature over an event is a floor on the span that starts there, never a reading of it; check a ledger's clock against the bracket, not the floor | managed |
| 57 | When two renderers must show the same header, give them one stylesheet and one markup shape, copied at build time | all |
| 58 | A model whose chat template thinks by default must be told not to on every plain call, and its reply's shape belongs in the prompt and a validator, not in the engine's grammar | all |
| 59 | Serve a static site that is rebuilt in place with Cache-Control: no-cache; without it the browser keeps old pages for a tenth of their age | all |
| 60 | Before a component goes in an architecture picture, find the line of code that calls it | all |
| 61 | Give an animated presentation a snapshot mode that draws each frame's final state at once, and photograph every frame before presenting it | all |
| 62 | Before a container changes the user it runs as, change the owner of the files it appends to in a shared, sticky directory; the kernel refuses even root | all |
| 63 | A static copy of a page whose answer comes from a model shows a call made once and labelled, offers only the questions recorded, and runs the rule's check again where it is built | structured |
| 64 | Run the accessibility check in every colour scheme a page ships; a palette that passes in light can fail in dark, and the reverse | all |
| 65 | Before making a shared directory's files private, list every process that reads them and the user each runs as | all |
| 66 | Pinning a self-signed certificate by making it the only trust anchor still checks its dates; an expired management-controller certificate fails the pin | all |
| 67 | Publish a running system as a recording, a record and notes; never as a static copy of its pages with the buttons disabled | all |
