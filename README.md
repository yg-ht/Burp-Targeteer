# Targeteer

A small Python extension for **Burp Suite Professional**, using the legacy Burp
Extender API and **Jython 2.7**. It turns in-scope, parameterised Proxy requests
into a manual testing queue in Burp's existing issues list.

## Installation

1. Configure the Jython standalone JAR under Burp's **Settings > Extensions >
   Python environment**. See [PortSwigger's setup instructions](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/troubleshooting).
2. Open your Burp project and configure **Target scope**.
3. Under **Extensions > Installed > Add**, choose **Python** and select
   `targeteer.py`. No pip packages are required. CPython 3 cannot load this file
   as a Burp extension.
4. Check the extension output for `Targeteer loaded`, then browse through Proxy.

## Behaviour

Every finding is named **Targeteer** and has **Tentative** confidence.

| Recognised parameters | Severity |
| --- | --- |
| URL query parameters (GET parameters, on any HTTP method) | Low |
| POST body parameters, with or without query parameters | Medium |

Body parameters include form fields (including multipart fields), JSON properties,
XML values and XML attributes recognised by Burp's request parser. Cookies,
headers, multipart metadata such as filenames, and bodies on non-POST methods
are excluded. Unsupported or unparseable bodies may yield no parameters.
Names are used exactly as returned by Burp; they are case-sensitive. Nested
JSON/XML names follow Burp's parser representation, not a custom path scheme.

A finding is created just before Proxy issues the request, without waiting for
a response. It contains a snapshot of that outgoing request. Responses and
requests from Repeater, Scanner and other tools are ignored. Targeteer neither
sends additional requests nor changes traffic. A request failure at the network
level does not remove its reminder. Later extensions may still modify traffic
after Targeteer's listener has run.

### Deduplication and triage

A signature consists of scheme, host, effective port, exact path, HTTP method,
the set of query parameter names and the set of POST body parameter names.
Host/scheme case and implicit versus explicit default ports are normalised.
Parameter values, order and duplicate occurrences of a name are ignored.
Different paths, methods, locations or name sets remain separate work items.
Adding, removing or renaming a key creates a new signature; returning to an
already-seen set does not.

For example, after triaging `/search?q=first` as **False positive**:

- `/search?q=second` does not create another finding.
- `/search?q=second&page=1` creates a new Low finding.
- `/search?term=second` creates a new Low finding.
- A POST to `/search` with body `q=second` creates a Medium finding.

Mark processed items as **False positive**, or use your normal triage workflow.
Targeteer remembers signatures independently of severity while loaded. On
reload, it restores signatures from existing Targeteer issue details, including
false positives, using the versioned marker in the final signature paragraph.
Signature-like text in parameter names is ignored. Keep those findings in the project
and save the project to retain the queue across restarts. Deleted findings are
still remembered until the extension is reloaded; after reload, deleted findings
can be raised again. Editing/removing the signature marker also prevents
restoration. There is no separate global history shared between projects.

Severity is a workflow priority, not evidence of a vulnerability. Parameter
names are HTML-escaped in issue details and values are excluded from signatures.
Original requests and URLs are retained as evidence and may contain credentials
or other sensitive data, just like other Burp findings. Evidence buffers are
managed by Burp; Targeteer does not write a separate traffic log.

## Verification

Run the dependency-free tests with Python 3:

```sh
python3 -m unittest discover -s tests -v
```

These tests use Burp/Java API doubles. They verify the extension's logic, not
Jython integration or Burp's own issue consolidation and project persistence.
Complete the following checks in Burp Professional before relying on the queue:

1. Proxy an in-scope GET `/search?q=one`: confirm one Targeteer / Low / Tentative
   finding and the captured request. Change `q`'s value: confirm no new finding.
2. Mark it False positive. Repeat with another value: confirm it stays closed.
   Add `page=1`: confirm a new Low finding remains separate from the false positive.
3. Proxy a POST form `name=one`: confirm Medium / Tentative. Change the value,
   reorder or repeat keys: confirm no duplicate. Add `role=user`: confirm a new
   Medium finding. Repeat using query plus body parameters and a JSON body.
4. Test an out-of-scope request, a parameter-free request, a cookie-only request
   and a Repeater request: none should produce a finding.
5. Save and reopen the project, then load Targeteer. Repeat the original keys
   with new values: confirm no new finding, including the false-positive case.
   Change a key: confirm a new finding. Also test unloading/reloading the
   extension in the same project.

The implementation uses [`IHttpListener`](https://portswigger.net/burp/extender/api/burp/ihttplistener.html),
[`IParameter`](https://portswigger.net/burp/extender/api/burp/iparameter.html), and
[`addScanIssue` / `getScanIssues`](https://portswigger.net/burp/extender/api/burp/iburpextendercallbacks.html).
Direct issue submission supports the Proxy-only workflow without enabling a
Scanner task. Only one instance of Targeteer should be loaded per project.

To stop creating reminders, unload the extension. Existing findings remain in
the Burp project and can be managed there.
