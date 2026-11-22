"""Bring your own scanner: any tool's CycloneDX CBOM, imported as evidence and scored.

A commercial or open-source discovery tool that exports a CycloneDX 1.6 or 1.7 CBOM can be brought to
the workbench without integrating it. Each cryptographic asset becomes a finding on a ledger of its
own (a run of kind `import`), labelled with the tool that made it and the hash of the document it came
from, and placed where the workbench can check it:

- an occurrence at a listener the scope lists (wire);
- an absolute path, with `--image` naming the scanned image, is a file in that image (host);
- `path` with a line number, with `--repo` and `--commit`, is a call site in a pinned repository (code).

Two shapes of document are read, chosen per component by what the component looks like, never by who
is said to have written it:

- **Components as assets.** One component per algorithm, certificate, key or protocol, the fact in the
  standard `cryptoProperties` fields and the place in `evidence.occurrences[].location` as `host:port`
  (the address or the name the scope gives the listener). A certificate's key family is read from the
  key it references (`subjectPublicKeyRef`, then that key's `algorithmRef`), then from a
  `Subject Public Key Algorithm` property, then from its own name.
- **Components as listeners** (a passive sensor's export). One protocol component per server, the
  facts in its properties (`Supported Groups`, `Key Exchange Algorithm`, `Host Key Algorithm`), the
  place as `src=<server>:<port>, dst=<client>, …`. Each property entry becomes the finding a scan of
  that listener would have made. A component located by its *destination* describes a client; it is
  counted and left out, since what a client offers says nothing about what the listener accepts.

Names are normalized by the same tables the workbench's own readers use, so an imported CBOM is scored
against the answer key on the same terms as ours, through the same function, with the same remediated
rule. An entry with no location the workbench can place stays out of the findings and is listed in the
import record under the reason: a CBOM entry nobody can find again cannot be verified or scored. A
component that exists only to be referenced (a certificate's key, a key's algorithm) is counted as
referenced, not as unplaced. What the document's author judged (`vulnerabilities`) is kept on the
record as that tool's report and is never a verdict here.
"""

from __future__ import annotations

import base64
import json
import re
from collections import Counter
from pathlib import Path

import yaml

from pqch import schemas, varmode
from pqch import scope as scope_mod
from pqch.common import sha256_hex, utc_now
from pqch.run import Run
from pqch.scout import names
from pqch.scout.normalize import _PRIMITIVE_ROLE, _Collector, fingerprint

HOSTPORT = re.compile(r"^\[?([A-Za-z0-9.:-]+?)\]?:(\d{1,5})$")
ACTOR = {"kind": "scanner", "id": "pqch-import"}
OBSERVED = ("accepted", "selected")

_SIDES = re.compile(r"\b(src|dst)=(\[?[A-Za-z0-9.:-]+?\]?)(?::(\d{1,5}))?(?=,|\s|$)")
_ACTIVE = re.compile(r"^Active discovery query for (\S+?):(\d{1,5})$")
_HEX_SUFFIX = re.compile(r"\s*\(0x[0-9a-fA-F]+\)\s*$")
_FAMILIES = ("RSA", "DSA", "ECDSA", "Ed25519", "Ed448")
_GENERIC_KEX = {"ECDH", "ECDHE", "DH", "DHE", "KEM", "ML-KEM", "MLKEM"}
_CURVES = {"P-256": "P-256", "P-384": "P-384", "P-521": "P-521", "secp256r1": "P-256", "secp384r1": "P-384",
           "secp521r1": "P-521", "prime256v1": "P-256", "nistp256": "P-256", "nistp384": "P-384", "nistp521": "P-521"}

_sig_names: dict[str, str] | None = None


def signature_names() -> dict[str, str]:
    """Certificate signature algorithms by any spelling the algorithm table knows, to the X.509 name."""
    global _sig_names
    if _sig_names is None:
        from pqch.policy import ROOT

        table = (yaml.safe_load((ROOT / "policy" / "algorithm-ids.yaml").read_text()) or {}).get("signature_names") or {}
        _sig_names = {**{v: v for v in table.values()}, **table}
    return _sig_names


def recognised(role: str, name: str) -> bool:
    """Whether the workbench knows what algorithm a name claims. A claim under a name no table holds
    cannot be called wrong by an answer key: it is reported as unrecognised, not as a false positive."""
    if role == "key-establishment":
        return (name in names.TLS_GROUPS.values() or name in names.TLS_GROUP_IDS.values() or name in names.SSH_KEX.values()
                or bool(re.fullmatch(r"(DH-\d+|DH-GEX|ffdhe\d+|RSA|ML-KEM-\d+)", name)))
    if role == "signature":
        return name in _FAMILIES or bool(re.fullmatch(r"(ML-DSA-\d+|SLH-DSA-[\w-]+|LMS|XMSS)", name))
    return True


def _props(comp: dict) -> dict:
    return {p.get("name"): p.get("value") for p in comp.get("properties") or [] if isinstance(p, dict)}


def _split(value: str | None) -> list[str]:
    """A property's comma-separated list, each entry without the tool's ` (0x….)` id suffix."""
    return [x for x in (_HEX_SUFFIX.sub("", v).strip() for v in (value or "").split(",")) if x]


def key_spelling(text: str) -> tuple[str, dict]:
    """A key algorithm spelled with its size or curve (`RSA-2048`, `ECDSA-P-256`, `DSA-1024`, `Ed25519`,
    an SSH host-key name) to (family, parameters). A family no table knows is returned as written."""
    text = (text or "").strip().removesuffix(" public key").removesuffix(" private key")
    if text in names.SSH_HOSTKEY:
        fam, params = names.SSH_HOSTKEY[text], {"ssh_names": [text]}
        if text in names.SSH_HOSTKEY_CURVE:
            params["curve"] = names.SSH_HOSTKEY_CURVE[text]
        return fam, params
    family = names.key_family(text)
    if family not in _FAMILIES:
        return (family if family != "unknown" else "unknown"), {}
    rest = text.split("-", 1)[1] if "-" in text else ""
    if family in ("RSA", "DSA") and rest.isdigit():
        return family, {"key_bits": int(rest)}
    if family == "ECDSA" and rest in _CURVES:
        return family, {"curve": _CURVES[rest]}
    return family, {}


def _tool(bom: dict, given: str | None = None) -> tuple[str, str]:
    """The tool that made the document. A writer lists the scanners it read before itself, so the
    author is the last entry of `metadata.tools` (1.4 list or 1.5+ components). A name given on the
    command line wins; its version is the document's only when the document names that tool."""
    t = (bom.get("metadata") or {}).get("tools") or {}
    items = [i for i in (t.get("components", []) if isinstance(t, dict) else t) if isinstance(i, dict)]
    if given:
        match = next((i for i in items if i.get("name") == given), None)
        return given, (match or {}).get("version") or "unstated"
    last = items[-1] if items else {}
    return last.get("name") or "unnamed tool", last.get("version") or "unstated"


def _asset(comp: dict, refs: dict) -> tuple[str, str, str, dict] | None:
    """(type, role, name, parameters) by the workbench's conventions, or None if not an asset."""
    if comp.get("type") != "cryptographic-asset":
        return None
    cp = comp.get("cryptoProperties") or {}
    kind = cp.get("assetType")
    name = comp.get("name") or "unknown"
    props = _props(comp)
    if kind == "algorithm":
        ap = cp.get("algorithmProperties") or {}
        prim = ap.get("primitive", "")
        role = _PRIMITIVE_ROLE.get(prim, "other")
        params: dict = {"primitive": prim} if prim else {}
        std = names.algorithm_name(name)
        if role == "signature":
            if name in signature_names():
                # A certificate's signature algorithm given a place of its own: a true statement about
                # the certificate, not a claim that the listener signs with a key of that family.
                return "algorithm", "other", signature_names()[name], {**params, "certificate_signature": True}
            family, more = key_spelling(name)
            if family in _FAMILIES:
                std, params = family, {**params, **more}
            if ap.get("curve") in _CURVES:
                params["curve"] = _CURVES[ap["curve"]]
        elif role == "key-establishment" and name.upper() in _GENERIC_KEX:
            # The family named generically, the group in the standard field beside it.
            group = ap.get("curve") or ap.get("parameterSetIdentifier")
            if group:
                std = names.TLS_GROUPS.get(str(group)) or names.algorithm_name(str(group))
                if name.upper() in ("ML-KEM", "MLKEM", "KEM") and str(group).isdigit():
                    std = f"ML-KEM-{group}"
        if ap.get("parameterSetIdentifier") and str(ap["parameterSetIdentifier"]).isdigit() and std in ("RSA", "DSA"):
            params["key_bits"] = int(ap["parameterSetIdentifier"])
        return "algorithm", role, std, params
    if kind == "certificate":
        cprops = cp.get("certificateProperties") or {}
        pub = refs.get(cprops.get("subjectPublicKeyRef")) or {}
        rcm = (pub.get("cryptoProperties") or {}).get("relatedCryptoMaterialProperties") or {}
        alg = refs.get(rcm.get("algorithmRef")) or {}
        family, more = "unknown", {}
        for spelling in (alg.get("name"), props.get("Subject Public Key Algorithm"), pub.get("name"), name):
            if spelling:
                family, more = key_spelling(spelling)
                if family in _FAMILIES or re.fullmatch(r"(ML-DSA-\d+|SLH-DSA-[\w-]+)", family):
                    break
                family, more = "unknown", {}
        sig = (refs.get(cprops.get("signatureAlgorithmRef")) or {}).get("name") or props.get("Signature Algorithm")
        ident = str(rcm.get("id") or "")
        params = {k: v for k, v in {
            "subject": cprops.get("subjectName"), "issuer": cprops.get("issuerName"),
            "not_before": cprops.get("notValidBefore"), "not_after": cprops.get("notValidAfter"),
            "signature": signature_names().get(sig, sig) if sig else None,
            "key_bits": rcm.get("size") if family in ("RSA", "DSA") else None,
            "spki_sha256": ident.split(":", 1)[1] if ident.startswith("spki-sha256:") else None,
        }.items() if v}
        return "certificate", "signature", family, {**more, **params}
    if kind == "related-crypto-material":
        rcm = cp.get("relatedCryptoMaterialProperties") or {}
        family, more = key_spelling(name)
        params = {**more, "kind": [rcm.get("type", "unknown")]}
        if rcm.get("size"):
            params["key_bits"] = rcm["size"]
        return "related-crypto-material", "other", family if family != "unknown" else names.key_family(name), params
    if kind == "protocol":
        pp = cp.get("protocolProperties") or {}
        version = _HEX_SUFFIX.sub("", str(pp.get("version") or "")).strip()
        if pp.get("type") in ("tls", "ssh") and version and "," not in version:
            return "protocol", "other", f"{pp['type'].upper()} {version.removeprefix('TLS ').removeprefix('SSH ')}", {}
        return "protocol", "other", name, {}
    return None


def _endpoint(scope: dict, host: str, port: int) -> dict | None:
    """The scoped listener at an address and port, or at the one name the scope gives a listener on
    that port. A name two listeners share on one port places nothing."""
    host = host.strip("[]")
    ep = next((e for e in scope["endpoints"] if e["host"] == host and e["port"] == port), None)
    if ep:
        return ep
    named = [e for e in scope["endpoints"] if e.get("sni") == host and e["port"] == port]
    return named[0] if len(named) == 1 else None


def _wire_subject(ep: dict) -> dict:
    return {"kind": "endpoint", "host": ep["host"], "port": ep["port"], "protocol": ep["protocol"],
            **({"sni": ep["sni"]} if ep.get("sni") else {})}


def locate(loc: str, scope: dict) -> tuple[str, dict | None]:
    """Where a wire occurrence points: ('server', listener) when it is located by a scoped listener
    speaking, ('client', listener) when by something speaking *to* one, ('elsewhere', None) for an
    address the scope does not list, ('', None) when the text names no address at all."""
    loc = loc.strip()
    m = HOSTPORT.match(loc) or _ACTIVE.match(loc)
    if m:
        ep = _endpoint(scope, m.group(1), int(m.group(2)))
        return ("server", ep) if ep else ("elsewhere", None)
    sides = {s: (h, int(p) if p else None) for s, h, p in _SIDES.findall(loc)}
    if not sides:
        return "", None
    for side, role in (("src", "server"), ("dst", "client")):
        host, port = sides.get(side, (None, None))
        if host and port is not None and (ep := _endpoint(scope, host, port)):
            return role, ep
    return "elsewhere", None


def place(loc: str, occ: dict, *, scope: dict, image: str | None, image_digest: str | None,
          repo: str | None, commit: str | None) -> tuple[str, dict] | None:
    """(layer, subject) for one occurrence, or None when the workbench cannot find it again."""
    role, ep = locate(loc, scope)
    if role == "server":
        return "wire", _wire_subject(ep)
    if role:
        return None
    line = occ.get("line")
    if repo and commit and line and not loc.startswith("/"):
        return "code", {"kind": "call-site", "repo": repo, "commit": commit, "path": loc, "line": int(line)}
    if loc.startswith("/") and image and image_digest:
        return "host", {"kind": "file", "image": image, "path": loc}
    return None


def _why(so_far: str, role: str) -> str:
    """Why a component found no place, the most telling reason of its occurrences: a client's side of
    a scoped listener, before an address out of scope, before no address at all."""
    order = ("no-location", "out-of-scope", "client-side")
    new = {"client": "client-side", "elsewhere": "out-of-scope"}.get(role, "no-location")
    return max(so_far, new, key=order.index)


def _is_listener_shape(comp: dict) -> bool:
    """A passive sensor's component: one per server, client or certificate seen, located by `src=`."""
    name = str(comp.get("name") or "")
    occs = (comp.get("evidence") or {}).get("occurrences") or []
    return name.startswith(("address=", "ja4=", "akid=")) or any(
        str(o.get("location", "")).startswith(("src=", "Active discovery query for ")) for o in occs)


def _leaf_of_chain(chain_b64: str) -> dict:
    """Identity of the served certificate from a `Chain` property (base64 of PEM, the leaf last)."""
    try:
        from pqch.scout.keys import parse_certificate_pem

        pem = base64.b64decode(chain_b64).decode()
        blocks = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem, re.S)
        return parse_certificate_pem(blocks[-1]) if blocks else {}
    except Exception:
        return {}


def _listener_shape(comp: dict, subject: dict, add, issuers: set[str]) -> None:
    """The findings a scan of the listener would have made, from one sensor component placed at it.
    `add(type, role, name, parameters)` records one; nothing is inferred beyond what a property states."""
    cp = comp.get("cryptoProperties") or {}
    props = _props(comp)
    name = str(comp.get("name") or "")
    if comp.get("type") == "library":
        # The software a server announced (an SSH banner): a fact about the protocol entry.
        if subject["protocol"] == "ssh":
            add("protocol", "other", "SSH 2.0", {"software": name})
        return
    kind = cp.get("assetType")
    if kind == "certificate":
        cprops = cp.get("certificateProperties") or {}
        family, more = key_spelling(props.get("Subject Public Key Algorithm") or "")
        sig = props.get("Signature Algorithm")
        m = re.search(r"serial=([0-9a-fA-F:]+)", name)
        ski = (props.get("Subject Key Identifier") or "").lower()
        params = {**more, **{k: v for k, v in {
            "subject": cprops.get("subjectName"), "issuer": cprops.get("issuerName"),
            "not_before": cprops.get("notValidBefore"), "not_after": cprops.get("notValidAfter"),
            "signature": signature_names().get(sig, sig) if sig else None,
            "serial": m.group(1).replace(":", "").lower().lstrip("0") if m else None,
        }.items() if v}}
        leaf = _leaf_of_chain(props["Chain"]) if props.get("Chain") else {}
        if leaf and leaf.get("serial") == params.get("serial"):
            params.update({k: leaf[k] for k in ("spki_sha256", "cert_sha256", "self_signed", "is_ca", "basic_constraints_ca") if k in leaf})
        if props.get("Active Query Caveat"):
            params["caveat"] = props["Active Query Caveat"][:300]
        if ski and ski in issuers:
            # A certificate another certificate at this listener names as its issuer: part of the chain
            # the server sent, not the key the listener signs with. Kept, and never a claim.
            add("certificate", "other", family, {**params, "chain_role": "issuer"})
        else:
            add("certificate", "signature", family, params)
        return
    if kind != "protocol":
        return
    pp = cp.get("protocolProperties") or {}
    ptype = str(pp.get("type") or "")
    suites = [{"name": _HEX_SUFFIX.sub("", s.get("name", "")).strip(),
               **({"id": m.group(1).lower()} if (m := re.search(r"\((0x[0-9a-fA-F]+)\)", s.get("name", ""))) else {})}
              for s in pp.get("cipherSuites") or [] if isinstance(s, dict)]
    if ptype == "tls":
        versions = [v.removeprefix("TLS ").strip() for v in _split(str(pp.get("version") or ""))]
        for v in versions:
            # A TLS 1.3 suite is one of the five RFC 8446 names (0x13xx); the rest belong to the
            # earlier versions the same component lists.
            mine = [s for s in suites if (s["name"].startswith(("TLS_AES_", "TLS_CHACHA20_")) and "_WITH_" not in s["name"]) == (v == "1.3")]
            add("protocol", "other", f"TLS {v}", {"suites": sorted(s["name"] for s in mine)} if mine else {})
        for g in _split(props.get("Supported Groups")):
            add("algorithm", "key-establishment", names.TLS_GROUPS.get(g, g), {"tool_names": [g]})
        for s in suites:
            if s["name"].startswith("TLS_RSA_WITH_"):
                add("algorithm", "key-establishment", "RSA", {"mode": "key-transport", "suites": [s["name"]]})
    elif ptype == "ssh":
        kex = [k for k in _split(props.get("Key Exchange Algorithm")) if not names.SSH_KEX_IGNORE.match(k)]
        for k in kex:
            add("algorithm", "key-establishment", names.SSH_KEX.get(k, k), {"ssh_names": [k]})
        for h in _split(props.get("Host Key Algorithm")):
            family, more = key_spelling(h)
            add("algorithm", "signature", family if family != "unknown" else h, more)
        version = _HEX_SUFFIX.sub("", str(pp.get("version") or "2.0")).strip() or "2.0"
        add("protocol", "other", f"SSH {version}", {k: v for k, v in {
            "encryption": _split(props.get("Encryption Algorithm")), "key_exchange": kex,
            "host_keys": _split(props.get("Host Key Algorithm"))}.items() if v})
    elif ptype:
        # A server seen speaking without encryption (the sensor's `pgsql`, `http`): the tool's report
        # of an exposure, kept as a protocol entry under the tool's own word for it.
        add("protocol", "other", f"{ptype} without TLS", {k: v for k, v in {"exposure": props.get("exposure")}.items() if v})


def _reference_targets(bom: dict) -> set[str]:
    """Every bom-ref another component points at: a key a certificate carries, an algorithm a key or a
    protocol uses. A component that is only a target has no place of its own by design."""
    out: set[str] = set()
    for c in bom.get("components") or []:
        cp = c.get("cryptoProperties") or {}
        cert, rcm, proto = (cp.get(k) or {} for k in ("certificateProperties", "relatedCryptoMaterialProperties", "protocolProperties"))
        out.update(str(r) for r in (cert.get("signatureAlgorithmRef"), cert.get("subjectPublicKeyRef"), rcm.get("algorithmRef"),
                                    rcm.get("securedBy", {}).get("algorithmRef") if isinstance(rcm.get("securedBy"), dict) else None) if r)
        out.update(str(r) for r in proto.get("cryptoRefArray") or [])
    return out


def _violations(bom: dict, by_ref: dict) -> list[dict]:
    """What the document's author judged, as it wrote it. A report, never a verdict of the workbench's."""
    out = []
    for v in bom.get("vulnerabilities") or []:
        if not isinstance(v, dict):
            continue
        out.append({k: val for k, val in {
            "id": v.get("id"), "source": (v.get("source") or {}).get("name"),
            "severity": next((r.get("severity") for r in v.get("ratings") or [] if isinstance(r, dict)), None),
            "detail": (v.get("detail") or v.get("description") or "")[:300] or None,
            "affects": [str((by_ref.get(a.get("ref")) or {}).get("name") or a.get("ref"))[:120]
                        for a in v.get("affects") or [] if isinstance(a, dict)][:20] or None}.items() if val})
    return out


def run_import(var: Path, docs: list[tuple[Path, str | None]], scope: dict, *, repo: str | None = None,
               commit: str | None = None, key_path: Path | None = None, tool: str | None = None,
               signer=None, observed: str | None = None, conditions: str | None = None,
               window: str | None = None) -> tuple[Run, dict]:
    """Import one or more CBOMs from one tool into a run of their own; each document may name the image
    it describes (`(path, image)`), as a tool that scans images one at a time writes one per image.

    `observed` says what the document's lists mean: `accepted` (everything the server will take, as an
    active scan finds) or `selected` (what the clients of the period chose, as a passive sensor sees).
    The two are different upper bounds under the same field names, so the record says which.
    `conditions` is the operator's statement of what drove the observation (the client mix, the export's
    period); `window` is the period the document covers. All three are recorded, none changes a score."""
    schemas.validate(scope)
    if observed and observed not in OBSERVED:
        raise ValueError(f"observed is one of {', '.join(OBSERVED)}")
    loaded = []
    for path, image in docs:
        raw = Path(path).read_bytes()
        bom = json.loads(raw)
        if bom.get("bomFormat") != "CycloneDX":
            raise ValueError(f"{path}: not a CycloneDX document")
        loaded.append((Path(path), image, raw, bom))
    name, version = _tool(loaded[0][3], tool)
    run = Run.start(var, scope, runner_scope_hash=scope_mod.scope_hash(scope), profile=f"import:{name}",
                    kind="import", runner_id="pqch-import")
    if key_path:
        run.commit_key(key_path, author="workbench")
    out_of: dict[str, list[str]] = {"no-location": [], "out-of-scope": [], "client-side": []}
    seen: Counter = Counter()
    left: Counter = Counter()
    documents, findings, reported = [], [], []
    appended: set[str] = set()
    repeated = 0
    for n, (path, image, raw, bom) in enumerate(loaded):
        digest = "sha256:" + sha256_hex(raw)
        stored = run.dir / f"imported-{n}.cdx.json"
        stored.write_bytes(raw)
        varmode.private(stored)
        documents.append({"name": path.name, "image": image, "path": str(stored.relative_to(var)), "sha256": digest,
                          "spec_version": bom.get("specVersion"),
                          "timestamp": (bom.get("metadata") or {}).get("timestamp")})
        image_digest = None
        if image:
            pinned = next((i for i in scope.get("images", []) if i.split("@")[0] == image), None)
            image_digest = pinned.split("@", 1)[1] if pinned and "@" in pinned else None
        job = {"tool": name, "version": _tool(bom, tool)[1], "image_digest": digest, "profile": f"import:{name}",
               "ended_at": utc_now(), "raw": str(stored.relative_to(var)), "raw_sha256": digest.split(":", 1)[1]}
        collectors: dict[str, _Collector] = {}
        comps = [c for c in bom.get("components") or [] if isinstance(c, dict)]
        refs = {c.get("bom-ref"): c for c in comps if c.get("bom-ref")}
        targets = _reference_targets(bom)
        reported += _violations(bom, refs)

        def collector(layer: str, collectors=collectors, job=job, image_digest=image_digest) -> _Collector:
            return collectors.setdefault(layer, _Collector(job, layer, subject_digest=image_digest if layer == "host" else None,
                                                           grade="reported"))

        # Which certificates at a listener another one there names as its issuer (authority key id ->
        # the issuer's subject key id): the chain a server sent, kept apart from the key it serves with.
        issuers: dict[tuple, set[str]] = {}
        for comp in comps:
            if (comp.get("cryptoProperties") or {}).get("assetType") != "certificate" or not _is_listener_shape(comp):
                continue
            m = re.search(r"akid=([0-9a-fA-F:]+)", str(comp.get("name") or ""))
            ski = (_props(comp).get("Subject Key Identifier") or "").lower()
            if m and m.group(1).lower() != ski:
                for occ in (comp.get("evidence") or {}).get("occurrences") or []:
                    role, ep = locate(str(occ.get("location", "")), scope)
                    if role == "server":
                        issuers.setdefault((ep["host"], ep["port"]), set()).add(m.group(1).lower())

        for comp in comps:
            sensor = _is_listener_shape(comp)
            a = None if sensor else _asset(comp, refs)
            if not sensor and not a:
                continue
            label = f"{(comp.get('cryptoProperties') or {}).get('assetType') or comp.get('type')} {comp.get('name')}"[:160]
            seen[(comp.get("cryptoProperties") or {}).get("assetType") or comp.get("type") or "other"] += 1
            occs = (comp.get("evidence") or {}).get("occurrences") or []
            if not sensor and _props(comp).get("pqch:kind") == "listener":
                left["listeners"] += 1  # the workbench's own listener summary; its members are components of their own
                continue
            if not occs and comp.get("bom-ref") in targets:
                left["referenced"] += 1
                continue
            placed, why = False, "no-location"
            for occ in occs:
                loc = str(occ.get("location", ""))
                if sensor:
                    role, ep = locate(loc, scope)
                    if role != "server":
                        why = _why(why, role)
                        continue
                    subject = _wire_subject(ep)
                    c = collector("wire")
                    excerpt = f"{comp.get('name')} at {loc}"[:400]
                    _listener_shape(comp, subject, lambda t, r, nm, pr, _s=subject, _c=c, _x=excerpt: _c.add(
                        _s, t, r, nm, {**pr, **({} if recognised(r, nm) else {"unrecognised_name": True})}, _x),
                        issuers.get((ep["host"], ep["port"]), set()))
                    placed = True
                    continue
                p = place(loc, occ, scope=scope, image=image, image_digest=image_digest, repo=repo, commit=commit)
                if not p:
                    why = _why(why, locate(loc, scope)[0])
                    continue
                layer, subject = p
                type_, role_, std, params = a[0], a[1], a[2], dict(a[3])
                if layer == "code":
                    params["line_text"] = occ.get("additionalContext", "")
                if layer == "wire" and type_ == "related-crypto-material" and subject["protocol"] == "ssh" \
                        and set(params.get("kind") or []) & {"public-key", "private-key"} and std in _FAMILIES:
                    # A host key reported as a key at an SSH listener is the listener's signature algorithm,
                    # which is how a scan of the listener records it.
                    type_, role_ = "algorithm", "signature"
                    params.pop("kind", None)
                if layer == "wire" and not recognised(role_, std):
                    params["unrecognised_name"] = True
                collector(layer).add(subject, type_, role_, std, params, f"{comp.get('name')} at {occ.get('location')}"
                                     + (f":{occ['line']}" if occ.get("line") else ""))
                placed = True
            if not placed:
                # By name only: where a component the scope does not hold was seen is the document's
                # business, and stays in the stored document.
                out_of[why].append(label)
        for layer, c in collectors.items():
            for f in c.findings():
                f["fingerprint"] = fingerprint(layer, f["subject"], f["asset"])
                schemas.validate(f)
                if f["fingerprint"] in appended:
                    repeated += 1  # the same fact in a later document of the same import
                    continue
                appended.add(f["fingerprint"])
                findings.append(f)
    for f in findings:
        run.ledger.append("finding.observed", ACTOR, f)
    unplaced = out_of["no-location"] + out_of["out-of-scope"]
    summary = {"tool": name, "version": version, "documents": documents,
               "assets": {str(k): v for k, v in seen.items()}, "findings": len(findings),
               "by_layer": dict(Counter(f["layer"] for f in findings)), "unplaced": len(unplaced),
               "unplaced_names": unplaced[:200],
               "left_out": {"no_location": len(out_of["no-location"]), "out_of_scope": len(out_of["out-of-scope"]),
                            "client_side": len(out_of["client-side"]), "referenced": left["referenced"],
                            "listeners": left["listeners"], "repeated": repeated,
                            "client_side_names": out_of["client-side"][:100]},
               "observation": {k: v for k, v in {"observed": observed, "conditions": conditions, "window": window}.items() if v}}
    if reported:
        summary["reported_violations"] = reported[:200]
    if key_path:
        from pqch.cbom import project
        from pqch.pipeline import remediated_rows
        from pqch.score import address_map, score_bom

        # A document of a copy of the estate: its listeners are at the copy's addresses, and the scope
        # names each one's original; the score maps them back and records the map (lesson 75). The
        # score is the one a scan gets: same function, same remediated rule, the whole row kept.
        amap = address_map(scope)
        key = yaml.safe_load(key_path.read_bytes())
        score = score_bom(project(list(run.ledger.events())), key, amap or None)
        remediated_rows(run.var, next(run.ledger.events()), key, [score["layers"]["wire"]])
        if amap:
            summary["copy"] = {**scope.get("copy", {}), "address_map": [
                {"host": h, "port": pt, "original": {"host": oh, "port": op}} for (h, pt), (oh, op) in sorted(amap.items())]}
        summary["score"] = score["layers"]
    run.ledger.append("import.completed", ACTOR, summary)
    run.close(signer)
    return run, summary
