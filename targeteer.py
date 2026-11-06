# -*- coding: utf-8 -*-
"""Targeteer: passive testing reminders for Burp Suite (Jython 2.7)."""

import hashlib
import json
import re
import threading

from burp import IBurpExtender, IHttpListener, IHttpRequestResponse, IParameter, IScanIssue
from java.lang import Exception as JavaException


SIGNATURE_LABEL = "Targeteer signature v1: "
# Only trust the final paragraph we generate. Parameter names are escaped, so
# they cannot introduce this markup even when they contain signature-like text.
SIGNATURE_PATTERN = re.compile(r"<p>Targeteer signature v1: ([0-9a-f]{64})</p>\s*\Z")
BODY_TYPES = (IParameter.PARAM_BODY, IParameter.PARAM_JSON,
              IParameter.PARAM_XML, IParameter.PARAM_XML_ATTR)


def escape_html(value):
    """Escape untrusted names before including them in Burp's HTML details."""
    return (value.replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;")
            .replace("'", "&#39;"))


def describe_request(info):
    """Return a value-independent identity and the recognised parameter names."""
    query_names = set()
    body_names = set()
    method = info.getMethod()
    for parameter in info.getParameters():
        if parameter.getType() == IParameter.PARAM_URL:
            query_names.add(parameter.getName())
        elif method == "POST" and parameter.getType() in BODY_TYPES:
            body_names.add(parameter.getName())
    if not query_names and not body_names:
        return None

    url = info.getUrl()
    port = url.getPort()
    if port == -1:
        port = url.getDefaultPort()
    query_names = sorted(query_names)
    body_names = sorted(body_names)
    identity = [1, url.getProtocol().lower(), url.getHost().lower(), port,
                url.getPath() or "/", method, query_names, body_names]
    serialised = json.dumps(identity, ensure_ascii=True, separators=(",", ":"))
    signature = hashlib.sha256(serialised.encode("ascii")).hexdigest()
    return signature, query_names, body_names


class RequestEvidence(IHttpRequestResponse):
    """Snapshot the outgoing request without accessing an unavailable response."""

    def __init__(self, message):
        self._request = message.getRequest()[:]
        self._service = message.getHttpService()
        self._response = None
        self._comment = None
        self._highlight = None

    def getRequest(self):
        return self._request

    def setRequest(self, request):
        self._request = request

    def getResponse(self):
        return self._response

    def setResponse(self, response):
        self._response = response

    def getHttpService(self):
        return self._service

    def setHttpService(self, service):
        self._service = service

    def getComment(self):
        return self._comment

    def setComment(self, comment):
        self._comment = comment

    def getHighlight(self):
        return self._highlight

    def setHighlight(self, highlight):
        self._highlight = highlight


class TargeteerIssue(IScanIssue):
    """A testing reminder, rather than a claim of a confirmed vulnerability."""

    def __init__(self, info, description, evidence):
        signature, query_names, body_names = description
        self._url = info.getUrl()
        self._evidence = evidence
        self._severity = "Medium" if body_names else "Low"
        details = ["<p>This in-scope Proxy request contains parameters that "
                   "may need manual testing.</p>",
                   "<p>HTTP method: <b>%s</b></p>" % escape_html(info.getMethod())]
        for label, names in (("GET / query", query_names), ("POST / body", body_names)):
            if names:
                details.append("<p>%s parameter names:</p><ul>%s</ul>" % (
                    label, "".join("<li>%s</li>" % escape_html(name) for name in names)))
        details.append("<p>After testing, mark this item as False positive or "
                       "use your normal issue triage workflow. Changes to values "
                       "alone will not create another item; a different set of "
                       "parameter names will.</p>")
        # A visible, versioned marker survives project saves and HTML sanitisation.
        # It also makes findings for different name sets distinct to Burp.
        details.append("<p>%s%s</p>" % (SIGNATURE_LABEL, signature))
        self._detail = "".join(details)

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return "Targeteer"

    def getIssueType(self):
        return 0  # Burp's extension-defined issue type.

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Tentative"

    def getIssueBackground(self):
        return ("Targeteer records parameterised requests as a manual testing "
                "queue. Severity indicates workflow priority; the presence of "
                "parameters does not establish a vulnerability.")

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return [self._evidence]

    def getHttpService(self):
        return self._evidence.getHttpService()


class BurpExtender(IBurpExtender, IHttpListener):
    """Observe Proxy requests without sending or modifying traffic."""

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._seen = set()
        self._lock = threading.RLock()
        callbacks.setExtensionName("Targeteer")
        try:
            # Restore all severities, including False positive, before listening.
            for issue in callbacks.getScanIssues(None):
                if issue.getIssueName() == "Targeteer":
                    match = SIGNATURE_PATTERN.search(issue.getIssueDetail() or "")
                    if match:
                        self._seen.add(match.group(1))
        except (Exception, JavaException):
            callbacks.printError("Targeteer could not restore existing findings. "
                                 "The listener was not started; reload the extension "
                                 "after checking that the Burp project is available.")
            raise
        callbacks.registerHttpListener(self)
        callbacks.printOutput("Targeteer loaded; restored %d parameter signatures."
                              % len(self._seen))

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if toolFlag != self._callbacks.TOOL_PROXY or not messageIsRequest:
            return
        try:
            info = self._helpers.analyzeRequest(messageInfo)
            if not self._callbacks.isInScope(info.getUrl()):
                return
            description = describe_request(info)
            if description is None:
                return
            signature = description[0]
            # Proxy callbacks can arrive concurrently. Only remember a signature
            # after submission succeeds, allowing a later request to retry failure.
            with self._lock:
                if signature in self._seen:
                    return
                evidence = self._callbacks.saveBuffersToTempFiles(RequestEvidence(messageInfo))
                self._callbacks.addScanIssue(TargeteerIssue(info, description, evidence))
                self._seen.add(signature)
        except (Exception, JavaException):
            # Parser/API exception messages can contain request secrets.
            self._callbacks.printError(
                "Targeteer could not record a Proxy request. Check the request "
                "format and Burp project availability; a later matching request "
                "will retry. Traffic has not been modified.")
