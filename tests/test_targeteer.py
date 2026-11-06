"""Behaviour tests with API doubles; run using CPython's standard library."""

import concurrent.futures
import copy
import importlib.util
import pathlib
import sys
import types
import unittest
from unittest.mock import patch
from urllib.parse import parse_qsl, urlsplit


burp = types.ModuleType("burp")
for interface in ("IBurpExtender", "IHttpListener", "IHttpRequestResponse", "IScanIssue"):
    setattr(burp, interface, type(interface, (object,), {}))
burp.IParameter = type("IParameter", (), dict(
    PARAM_URL=0, PARAM_BODY=1, PARAM_COOKIE=2, PARAM_XML=3,
    PARAM_XML_ATTR=4, PARAM_MULTIPART_ATTR=5, PARAM_JSON=6))
java = types.ModuleType("java")
java_lang = types.ModuleType("java.lang")
java_lang.Exception = type("JavaException", (Exception,), {})
spec = importlib.util.spec_from_file_location(
    "targeteer", pathlib.Path(__file__).resolve().parents[1] / "targeteer.py")
targeteer = importlib.util.module_from_spec(spec)
with patch.dict(sys.modules, {"burp": burp, "java": java, "java.lang": java_lang}):
    spec.loader.exec_module(targeteer)


class URL:
    def __init__(self, value):
        self.parts = urlsplit(value)

    def getProtocol(self):
        return self.parts.scheme

    def getHost(self):
        return self.parts.hostname

    def getPort(self):
        return self.parts.port if self.parts.port is not None else -1

    def getDefaultPort(self):
        return {"http": 80, "https": 443}[self.parts.scheme]

    def getPath(self):
        return self.parts.path


class Parameter:
    def __init__(self, kind, name):
        self.kind = kind
        self.name = name

    def getType(self):
        return self.kind

    def getName(self):
        return self.name

    def getValue(self):
        raise AssertionError("Deduplication must never read parameter values")


class RequestInfo:
    def __init__(self, url="https://example.test/search?q=one", method="GET", body="", extra=()):
        self.url = URL(url)
        self.method = method
        self.parameters = [Parameter(0, name) for name, _ in
                           parse_qsl(self.url.parts.query, keep_blank_values=True)]
        self.parameters.extend(Parameter(1, name) for name, _ in
                               parse_qsl(body, keep_blank_values=True))
        self.parameters.extend(extra)

    def getUrl(self):
        return self.url

    def getMethod(self):
        return self.method

    def getParameters(self):
        return self.parameters


class Message:
    def __init__(self, info):
        self.info = info
        self.request = bytearray(b"GET /search?q=one HTTP/1.1\r\nHost: example.test\r\n\r\n")
        self.service = object()

    def getRequest(self):
        return self.request

    def getHttpService(self):
        return self.service

    def getResponse(self):
        raise AssertionError("Responses are unavailable on outgoing requests")


class Callbacks:
    TOOL_PROXY = 4

    def __init__(self, issues=()):
        self.issues = list(issues)
        self.errors = []
        self.in_scope = True
        self.fail_submission = False
        self.fail_restore = False
        self.fail_evidence = False
        self.listener = None

    def getHelpers(self):
        return self

    def setExtensionName(self, name):
        self.name = name

    def getScanIssues(self, prefix):
        if self.fail_restore:
            raise java_lang.Exception("private-project-detail")
        return self.issues

    def registerHttpListener(self, listener):
        self.listener = listener

    def printOutput(self, text):
        self.output = text

    def printError(self, text):
        self.errors.append(text)

    def analyzeRequest(self, message):
        return message.info

    def isInScope(self, url):
        self.scope_url = url
        return self.in_scope

    def saveBuffersToTempFiles(self, message):
        if self.fail_evidence:
            raise java_lang.Exception("secret request")
        assert message.getResponse() is None
        return message

    def addScanIssue(self, issue):
        if self.fail_submission:
            raise java_lang.Exception("secret request")
        self.issues.append(issue)


class TargeteerTests(unittest.TestCase):
    def setUp(self):
        self.callbacks = Callbacks()
        self.extension = targeteer.BurpExtender()
        self.extension.registerExtenderCallbacks(self.callbacks)

    def send(self, tool=4, is_request=True, **kwargs):
        message = Message(RequestInfo(**kwargs))
        self.extension.processHttpMessage(tool, is_request, message)
        return message

    def reload(self):
        self.extension = targeteer.BurpExtender()
        self.extension.registerExtenderCallbacks(self.callbacks)

    def test_get_metadata_and_snapshot(self):
        message = self.send()
        issue = self.callbacks.issues[0]
        self.assertEqual("Targeteer", self.callbacks.name)
        self.assertIs(self.extension, self.callbacks.listener)
        self.assertEqual("Targeteer", issue.getIssueName())
        self.assertEqual("Low", issue.getSeverity())
        self.assertEqual("Tentative", issue.getConfidence())
        evidence = issue.getHttpMessages()[0]
        self.assertEqual(message.request, evidence.getRequest())
        message.request[0] = 0
        self.assertNotEqual(message.request, evidence.getRequest())
        self.assertIs(message.service, issue.getHttpService())
        self.assertIsNone(evidence.getResponse())

    def test_post_and_mixed_parameters_are_medium(self):
        for url in ("https://example.test/form", "https://example.test/form?q=one"):
            self.send(url=url, method="POST", body="name=one")
        self.assertEqual(["Medium", "Medium"], [i.getSeverity() for i in self.callbacks.issues])
        self.assertTrue(all(i.getConfidence() == "Tentative" for i in self.callbacks.issues))

    def test_values_order_duplicates_and_empty_values_do_not_repeat(self):
        for query in ("q=one&page=1", "page=2&q=two", "q=&page=", "q=3&q=4&page=5"):
            self.send(url="https://example.test/search?" + query)
        self.assertEqual(1, len(self.callbacks.issues))
        for body in ("x=1&y=2", "y=3&x=4", "x=&y=&x=again"):
            self.send(method="POST", body=body)
        self.assertEqual(2, len(self.callbacks.issues))

    def test_false_positive_new_names_then_reload(self):
        self.send()
        original = self.callbacks.issues[0]
        original._severity = "False positive"
        self.send(url="https://example.test/search?q=two")
        self.assertEqual(1, len(self.callbacks.issues))
        self.send(url="https://example.test/search?q=two&page=1")
        self.assertEqual(2, len(self.callbacks.issues))
        self.assertEqual("False positive", original.getSeverity())
        self.reload()
        self.send(url="https://example.test/search?q=three")
        self.send(url="https://example.test/search?page=9&q=four")
        self.assertEqual(2, len(self.callbacks.issues))
        self.send(url="https://example.test/search?term=five")
        self.assertEqual(3, len(self.callbacks.issues))

    def test_post_false_positive_names_change_but_values_do_not(self):
        self.send(method="POST", body="name=one")
        self.callbacks.issues[0]._severity = "False positive"
        self.reload()
        self.send(method="POST", body="name=two")
        self.assertEqual(1, len(self.callbacks.issues))
        self.send(method="POST", body="name=two&role=user")
        self.send(method="POST", body="role=user")
        self.assertEqual(3, len(self.callbacks.issues))

    def test_endpoint_method_location_and_case_are_distinct(self):
        requests = [dict(), dict(url="http://example.test/search?q=1"),
                    dict(url="https://other.test/search?q=1"),
                    dict(url="https://example.test:8443/search?q=1"),
                    dict(url="https://example.test/other?q=1"),
                    dict(method="POST"),
                    dict(url="https://example.test/search", method="POST", body="q=1"),
                    dict(url="https://example.test/search?Q=1")]
        for kwargs in requests:
            self.send(**kwargs)
        self.assertEqual(len(requests), len(self.callbacks.issues))

    def test_default_port_host_case_and_empty_path_normalise(self):
        for url in ("https://EXAMPLE.test?q=1", "https://example.test:443/?q=2"):
            self.send(url=url)
        self.assertEqual(1, len(self.callbacks.issues))

    def test_only_in_scope_proxy_requests(self):
        self.send(tool=64)
        self.send(is_request=False)
        self.callbacks.in_scope = False
        self.send()
        self.assertEqual([], self.callbacks.issues)
        self.callbacks.in_scope = True
        self.send()
        self.assertEqual(1, len(self.callbacks.issues))

    def test_empty_cookies_metadata_and_non_post_bodies_are_ignored(self):
        for kwargs in (dict(), dict(extra=[Parameter(2, "session")]),
                       dict(method="POST", extra=[Parameter(5, "filename")]),
                       dict(method="PUT", body="name=value")):
            self.send(url="https://example.test/", **kwargs)
        self.assertEqual([], self.callbacks.issues)

    def test_burp_parsed_structured_body_parameters(self):
        for kind in (1, 3, 4, 6):
            with self.subTest(kind=kind):
                self.send(url="https://example.test/%d" % kind, method="POST",
                          extra=[Parameter(kind, "name")])
                self.assertEqual("Medium", self.callbacks.issues[-1].getSeverity())
        self.assertEqual(4, len(self.callbacks.issues))

    def test_escaping_unicode_and_unambiguous_name_sets(self):
        self.send(extra=[Parameter(0, '<script>"&\'\u00e9')])
        detail = self.callbacks.issues[0].getIssueDetail()
        self.assertNotIn("<script>", detail)
        self.assertIn("&lt;script&gt;&quot;&amp;&#39;\u00e9", detail)
        self.send(extra=[Parameter(0, "a,b")])
        self.send(extra=[Parameter(0, "a"), Parameter(0, "b")])
        self.assertEqual(3, len(self.callbacks.issues))

    def test_empty_name_and_many_parameters(self):
        self.send(url="https://example.test/?=one")
        self.send(url="https://example.test/?=two")
        self.assertEqual(1, len(self.callbacks.issues))
        names = [Parameter(0, "p%d" % i) for i in range(2000)]
        self.send(extra=names)
        self.send(extra=list(reversed(names)))
        self.assertEqual(2, len(self.callbacks.issues))

    def test_concurrent_duplicates_submit_once(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            list(pool.map(lambda _: self.send(), range(100)))
        self.assertEqual(1, len(self.callbacks.issues))

    def test_failed_submission_and_evidence_can_retry_without_leaking_secrets(self):
        for failure in ("fail_submission", "fail_evidence"):
            with self.subTest(failure=failure):
                self.setUp()
                setattr(self.callbacks, failure, True)
                self.send()
                self.assertEqual([], self.callbacks.issues)
                self.assertEqual(1, len(self.callbacks.errors))
                self.assertNotIn("secret request", self.callbacks.errors[0])
                setattr(self.callbacks, failure, False)
                self.send()
                self.assertEqual(1, len(self.callbacks.issues))

    def test_malformed_request_does_not_escape_listener_or_poison_history(self):
        with patch.object(self.callbacks, "analyzeRequest", side_effect=ValueError("secret")):
            self.send()
        self.assertEqual(1, len(self.callbacks.errors))
        self.assertNotIn("secret", self.callbacks.errors[0])
        self.send()
        self.assertEqual(1, len(self.callbacks.issues))

    def test_restoration_failure_prevents_listener_registration(self):
        callbacks = Callbacks()
        callbacks.fail_restore = True
        with self.assertRaises(java_lang.Exception):
            targeteer.BurpExtender().registerExtenderCallbacks(callbacks)
        self.assertIsNone(callbacks.listener)
        self.assertEqual(1, len(callbacks.errors))

    def test_restores_from_details_without_relying_on_python_issue_objects(self):
        self.send()
        saved_detail = self.callbacks.issues[0].getIssueDetail()
        saved = types.SimpleNamespace(getIssueName=lambda: "Targeteer",
                                      getIssueDetail=lambda: saved_detail)
        self.callbacks.issues = [saved]
        self.reload()
        self.send()
        self.assertEqual(1, len(self.callbacks.issues))

    def test_other_issues_and_invalid_markers_do_not_suppress_requests(self):
        self.send()
        original = self.callbacks.issues.pop()
        unrelated = copy.copy(original)
        unrelated.getIssueName = lambda: "Another extension"
        malformed = copy.copy(original)
        malformed._detail = "Targeteer signature v1: bad"
        empty = copy.copy(original)
        empty._detail = None
        self.callbacks.issues = [unrelated, malformed, empty]
        self.reload()
        self.send()
        self.assertEqual(4, len(self.callbacks.issues))

    def test_deleted_findings_stay_seen_until_reload(self):
        self.send()
        self.callbacks.issues.clear()
        self.send()
        self.assertEqual([], self.callbacks.issues)
        self.reload()
        self.send()
        self.assertEqual(1, len(self.callbacks.issues))


if __name__ == "__main__":
    unittest.main()
