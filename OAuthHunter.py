# -*- coding: utf-8 -*-
"""
OAuthHunter v1.1 - Generic OAuth 2.0 / OIDC / SAML Vulnerability Scanner
Burp Suite Extension - Jython 2.7 Compatible

Install: Extender > Extensions > Add > Type: Python > Select this file
Requires: Burp Suite Pro + Jython 2.7 standalone jar
"""

from burp import IBurpExtender, IHttpListener, ITab, IExtensionStateListener
from javax.swing import (JPanel, JTabbedPane, JTable, JScrollPane, JButton,
                          JTextArea, JLabel, JSplitPane, JTextField,
                          BorderFactory, SwingUtilities, JOptionPane,
                          JTree, BoxLayout, SwingConstants)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from javax.swing.tree import DefaultMutableTreeNode, DefaultTreeModel
from java.awt import (Color, Font, Dimension, BorderLayout, GridBagLayout,
                       GridBagConstraints, Insets, FlowLayout)
from java.awt.event import ActionListener, MouseAdapter
from java.lang import Runnable

import json
import base64
import time
from collections import defaultdict

# ── Colours ──────────────────────────────────
C_BG      = Color(18,  18,  24)
C_SURFACE = Color(28,  28,  38)
C_BORDER  = Color(45,  45,  60)
C_ACCENT  = Color(99,  179, 237)
C_RED     = Color(252, 90,  90)
C_GREEN   = Color(72,  199, 142)
C_YELLOW  = Color(255, 220, 80)
C_TEXT    = Color(220, 220, 235)
C_MUTED   = Color(120, 120, 150)

SEVERITY_COLORS = {
    "CRITICAL": Color(255, 60,  60),
    "HIGH":     Color(255, 130, 60),
    "MEDIUM":   Color(255, 210, 60),
    "LOW":      Color(72,  199, 142),
    "INFO":     Color(99,  179, 237),
}

# ── OAuth/SAML detection signatures ──────────
OAUTH_PARAMS = [
    "response_type", "client_id", "redirect_uri", "scope", "state",
    "code", "access_token", "id_token", "grant_type", "code_verifier",
    "code_challenge", "nonce", "prompt", "RelayState", "SAMLResponse",
    "SAMLRequest", "returnTo", "return_to", "next", "redirect", "goto",
    "continue", "postLogin", "landingPage", "g2g", "eg2g", "q2gExpiry",
    "wresult", "wctx", "wa", "token_type", "refresh_token",
]

OAUTH_PATHS = [
    "/authorize", "/oauth/authorize", "/oauth2/authorize",
    "/login/callback", "/auth/callback", "/oauth/callback",
    "/saml/acs", "/saml2/acs", "/sso/saml",
    "/token", "/oauth/token", "/oauth2/token",
    "/userinfo", "/authorize/resume",
    "/conversion/interceptor", "/auth/interceptor",
    "/.well-known/openid-configuration",
    "/usernamepassword/login", "/login/resume",
]

REDIRECT_PARAMS = [
    "redirect_uri", "returnTo", "return_to", "next", "redirect",
    "goto", "continue", "url", "target", "dest", "destination",
    "postLogin", "landingPage", "after_login", "callback",
    "redirect_url", "return_url", "success_url", "forward",
]

# ── Vulnerability definitions ─────────────────
VULN_CHECKS = {
    "open_redirect_absolute": {
        "name":        "Open Redirect via OAuth Redirect URI",
        "severity":    "HIGH",
        "cwe":         "CWE-601",
        "description": "redirect_uri accepts absolute external URLs - attacker can steal auth code",
        "payloads": [
            "https://evil.com",
            "//evil.com",
            "https://evil.com%40{host}",
            "https://{host}.evil.com",
            "{collab}",
        ],
    },
    "redirect_uri_prefix_bypass": {
        "name":        "Redirect URI Prefix Match Bypass",
        "severity":    "HIGH",
        "cwe":         "CWE-183",
        "description": "redirect_uri validated by prefix only - append query params or path traversal",
        "payloads": [
            "{redirect_uri}?next=/admin",
            "{redirect_uri}?returnTo=/admin",
            "{redirect_uri}?redirect=/admin",
            "{redirect_uri}/../../../admin",
            "{redirect_uri}%2f..%2f..%2fadmin",
            "{redirect_uri}#/admin",
            "{redirect_uri}%23/admin",
            "{redirect_uri}?goto={collab}",
        ],
    },
    "state_missing": {
        "name":        "Missing OAuth State Parameter (CSRF)",
        "severity":    "HIGH",
        "cwe":         "CWE-352",
        "description": "No state in authorization request - CSRF login attack possible",
        "payloads": [],
    },
    "state_predictable": {
        "name":        "Predictable / Reusable OAuth State",
        "severity":    "MEDIUM",
        "cwe":         "CWE-330",
        "description": "State is short, numeric, or static - may be guessable or reusable",
        "payloads": [],
    },
    "state_jwt_tamperable": {
        "name":        "OAuth State JWT Contains Redirect Destination",
        "severity":    "HIGH",
        "cwe":         "CWE-74",
        "description": "State JWT encodes returnTo/redirect - tamper to bypass post-auth redirect",
        "payloads": [
            "eyJyZXR1cm5UbyI6Ii9hZG1pbiJ9.e30.",
            "eyJyZXR1cm5UbyI6Ii9hZG1pbiIsInJvbGUiOiJhZG1pbiJ9.e30.",
        ],
    },
    "implicit_flow": {
        "name":        "OAuth Implicit Flow in Use",
        "severity":    "MEDIUM",
        "cwe":         "CWE-522",
        "description": "response_type=token exposes access token in URL fragment",
        "payloads": [],
    },
    "pkce_missing": {
        "name":        "PKCE Not Enforced on Authorization Code Flow",
        "severity":    "MEDIUM",
        "cwe":         "CWE-345",
        "description": "No code_challenge/verifier - auth code interception attack possible",
        "payloads": [],
    },
    "scope_escalation": {
        "name":        "OAuth Scope Escalation",
        "severity":    "HIGH",
        "cwe":         "CWE-269",
        "description": "Server may accept elevated scopes beyond what was originally requested",
        "payloads": [
            "openid profile email admin",
            "openid profile email offline_access",
            "read write admin delete",
            "{scope} admin",
            "{scope} offline_access",
            "intercept openid profile",
            "openid",
        ],
    },
    "token_in_url": {
        "name":        "Token Exposed in URL / Location Header",
        "severity":    "MEDIUM",
        "cwe":         "CWE-598",
        "description": "access_token or id_token in URL - logged in browser history/server logs",
        "payloads": [],
    },
    "redirect_param_injection": {
        "name":        "Post-Auth Redirect Parameter Injection",
        "severity":    "MEDIUM",
        "cwe":         "CWE-601",
        "description": "App reads post-login destination from unvalidated URL/cookie parameter",
        "payloads": [
            "/admin",
            "/admin/users",
            "//admin",
            "/%2Fadmin",
            "/admin%00",
            "/%5cadmin",
            "/admin#bypass",
            "{collab}",
        ],
    },
    "cookie_no_flags": {
        "name":        "Auth Cookie Missing Security Flags",
        "severity":    "LOW",
        "cwe":         "CWE-614",
        "description": "Auth-related cookies missing HttpOnly, Secure, or SameSite flags",
        "payloads": [],
    },
    "saml_relaystate_redirect": {
        "name":        "SAML RelayState Open Redirect",
        "severity":    "HIGH",
        "cwe":         "CWE-601",
        "description": "RelayState used as post-auth redirect without host validation",
        "payloads": [
            "https://evil.com",
            "//evil.com",
            "/admin",
            "{collab}",
        ],
    },
    "interceptor_bypass": {
        "name":        "Post-Auth Forced Redirect / Interceptor Bypass",
        "severity":    "HIGH",
        "cwe":         "CWE-284",
        "description": "App enforces post-login redirect to fixed page - bypass via cookie/param",
        "payloads": [
            "g2g=false",
            "g2g=0",
            "eg2g=false",
            "?skip=true",
            "?bypass=1",
            "?debug=true",
            "?locale=en_CA",
        ],
    },
    "error_info_disclosure": {
        "name":        "OAuth Error Response Reveals Internal Config",
        "severity":    "MEDIUM",
        "cwe":         "CWE-209",
        "description": "error_description reveals callback URL whitelist or internal routing info",
        "payloads": [],
    },
}


# ── Non-editable table model ──────────────────
class ReadOnlyTableModel(DefaultTableModel):
    def isCellEditable(self, row, col):
        return False


# ── Cell renderers ────────────────────────────
class SeverityRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected,
                                       hasFocus, row, col):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, col)
        if col == 2:
            self.setForeground(SEVERITY_COLORS.get(str(value), C_TEXT))
            self.setFont(Font("Monospaced", Font.BOLD, 11))
        else:
            self.setForeground(C_TEXT)
            self.setFont(Font("Monospaced", Font.PLAIN, 11))
        self.setBackground(C_SURFACE if not isSelected else C_ACCENT.darker())
        return c


class ResultRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected,
                                       hasFocus, row, col):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, col)
        if col == 1:
            self.setForeground(C_GREEN if str(value) == "HIT" else C_MUTED)
            self.setFont(Font("Monospaced", Font.BOLD, 11))
        else:
            self.setForeground(C_TEXT)
            self.setFont(Font("Monospaced", Font.PLAIN, 11))
        self.setBackground(C_SURFACE if not isSelected else C_ACCENT.darker())
        return c


# ── Action listeners ──────────────────────────
class PauseAction(ActionListener):
    def __init__(self, ext, btn):
        self.ext = ext
        self.btn = btn

    def actionPerformed(self, evt):
        self.ext._paused = not self.ext._paused
        if self.ext._paused:
            self.btn.setText("Resume")
            self.btn.setForeground(C_GREEN)
        else:
            self.btn.setText("Pause")
            self.btn.setForeground(C_YELLOW)


class ClearAction(ActionListener):
    def __init__(self, ext):
        self.ext = ext

    def actionPerformed(self, evt):
        e = self.ext
        e.all_findings = []
        e.flows.clear()
        e._findings_model.setRowCount(0)
        e._active_model.setRowCount(0)
        e._flow_root.removeAllChildren()
        e._flow_tree_model.reload()
        e._log("Cleared all findings and flows.")


class ExportAction(ActionListener):
    def __init__(self, ext):
        self.ext = ext

    def actionPerformed(self, evt):
        try:
            data = []
            for f in self.ext.all_findings:
                data.append({k: v for k, v in f.items()
                              if k != "messageInfo"})
            path = "/tmp/oauthhunter_findings.json"
            with open(path, "w") as fp:
                json.dump(data, fp, indent=2, default=str)
            self.ext._log("Exported to " + path)
            JOptionPane.showMessageDialog(
                None, "Saved to " + path, "Export OK",
                JOptionPane.INFORMATION_MESSAGE)
        except Exception as ex:
            self.ext._log("Export error: " + str(ex))


class SaveSettingsAction(ActionListener):
    def __init__(self, ext, collab_field, scope_field):
        self.ext          = ext
        self.collab_field = collab_field
        self.scope_field  = scope_field

    def actionPerformed(self, evt):
        self.ext.collab_url   = self.collab_field.getText().strip()
        self.ext.scope_filter = [s.strip() for s in
                                  self.scope_field.getText().split(",")
                                  if s.strip()]
        self.ext._log("Settings saved. Collaborator: " + self.ext.collab_url)


class AttackAction(ActionListener):
    def __init__(self, ext, table):
        self.ext   = ext
        self.table = table

    def actionPerformed(self, evt):
        row = self.table.getSelectedRow()
        if 0 <= row < len(self.ext.all_findings):
            f = self.ext.all_findings[row]
            self.ext.launch_active_tests(
                f["host"], f["vuln_type"], f["messageInfo"])
            self.ext._tabs.setSelectedIndex(2)


class FindingSelectListener(MouseAdapter):
    def __init__(self, ext, table, detail):
        self.ext    = ext
        self.table  = table
        self.detail = detail

    def mouseClicked(self, evt):
        row = self.table.getSelectedRow()
        if 0 <= row < len(self.ext.all_findings):
            f = self.ext.all_findings[row]
            payloads = VULN_CHECKS.get(f["vuln_type"], {}).get("payloads", [])
            text = (
                "Name:        {}\n"
                "Severity:    {}\n"
                "CWE:         {}\n"
                "Host:        {}\n"
                "Path:        {}\n"
                "Confidence:  {}\n"
                "Time:        {}\n\n"
                "Description:\n{}\n\n"
                "Observed Params:\n{}\n\n"
                "Payloads to Test:\n{}"
            ).format(
                f["name"], f["severity"], f["cwe"],
                f["host"], f["path"], f["confidence"],
                f["timestamp"], f["description"],
                json.dumps(f.get("params", {}), indent=2, default=str)[:600],
                "\n".join(payloads) if payloads else "(passive detection only)"
            )
            self.detail.setText(text)
            self.detail.setCaretPosition(0)


class TreeSelectListener(MouseAdapter):
    def __init__(self, ext, tree, detail):
        self.ext    = ext
        self.tree   = tree
        self.detail = detail

    def mouseClicked(self, evt):
        path = self.tree.getSelectionPath()
        if not path:
            return
        label = str(path.getLastPathComponent())
        flow = self.ext.flows.get(label)
        if flow:
            self.detail.setText(json.dumps(flow.to_dict(), indent=2))
            self.detail.setCaretPosition(0)


class PayloadBtnAction(ActionListener):
    def __init__(self, text, area):
        self.text = text
        self.area = area

    def actionPerformed(self, evt):
        self.area.setText(self.text)
        self.area.setCaretPosition(0)


class ClearLogAction(ActionListener):
    def __init__(self, area):
        self.area = area

    def actionPerformed(self, evt):
        self.area.setText("")


# ── Runnable UI updaters ──────────────────────
class RefreshFindingsTable(Runnable):
    def __init__(self, ext):
        self.ext = ext

    def run(self):
        try:
            m = self.ext._findings_model
            m.setRowCount(0)
            for f in self.ext.all_findings:
                m.addRow([f["timestamp"], f["host"], f["severity"],
                           f["name"], f["path"][:55],
                           f["confidence"], f["cwe"]])
        except Exception:
            pass


class RefreshFlowTree(Runnable):
    def __init__(self, ext, host, flow):
        self.ext  = ext
        self.host = host
        self.flow = flow

    def run(self):
        try:
            root      = self.ext._flow_root
            host_node = None
            for i in range(root.getChildCount()):
                if str(root.getChildAt(i)) == self.host:
                    host_node = root.getChildAt(i)
                    break
            if host_node is None:
                host_node = DefaultMutableTreeNode(self.host)
                root.add(host_node)
            host_node.removeAllChildren()

            f = self.flow
            host_node.add(DefaultMutableTreeNode("Type: " + f.flow_type))
            host_node.add(DefaultMutableTreeNode(
                "Requests: " + str(len(f.requests))))
            host_node.add(DefaultMutableTreeNode(
                "PKCE: " + ("YES" if f.has_pkce else "NO")))
            host_node.add(DefaultMutableTreeNode(
                "Findings: " + str(len(f.findings))))

            if f.client_ids:
                n = DefaultMutableTreeNode("Client IDs")
                for cid in f.client_ids:
                    n.add(DefaultMutableTreeNode(cid[:50]))
                host_node.add(n)
            if f.redirect_uris:
                n = DefaultMutableTreeNode("Redirect URIs")
                for ru in f.redirect_uris:
                    n.add(DefaultMutableTreeNode(ru[:60]))
                host_node.add(n)
            if f.scopes:
                n = DefaultMutableTreeNode("Scopes")
                for s in f.scopes:
                    n.add(DefaultMutableTreeNode(s))
                host_node.add(n)
            if f.state_values:
                n = DefaultMutableTreeNode("States: " + str(len(f.state_values)))
                for sv in f.state_values[-3:]:
                    n.add(DefaultMutableTreeNode(sv[:50]))
                host_node.add(n)

            self.ext._flow_tree_model.reload()
            self.ext._flow_tree.expandRow(0)
        except Exception:
            pass


class AppendLog(Runnable):
    def __init__(self, ext, line):
        self.ext  = ext
        self.line = line

    def run(self):
        try:
            a = self.ext._log_area
            a.append(self.line)
            a.setCaretPosition(a.getDocument().getLength())
        except Exception:
            pass


class AppendActiveResult(Runnable):
    def __init__(self, ext, result):
        self.ext    = ext
        self.result = result

    def run(self):
        try:
            r = self.result
            self.ext._active_model.addRow([
                r["timestamp"],
                "HIT" if r["success"] else "miss",
                r["vuln_type"],
                r["payload"],
                str(r["status"]),
                r["location"],
            ])
            if r["success"]:
                self.ext._log("[HIT] {} | {} -> {} {}".format(
                    r["vuln_type"], r["payload"][:40],
                    r["status"], r["location"][:60]))
        except Exception:
            pass


# ── Active test runner ────────────────────────
class ActiveTestRunner(Runnable):
    def __init__(self, ext, host, vuln_type, original_msg):
        self.ext          = ext
        self.host         = host
        self.vuln_type    = vuln_type
        self.original_msg = original_msg

    def run(self):
        e        = self.ext
        check    = VULN_CHECKS.get(self.vuln_type, {})
        payloads = check.get("payloads", [])

        if not payloads:
            e._log("No active payloads defined for: " + self.vuln_type)
            return

        analyzed = e._helpers.analyzeRequest(self.original_msg)
        params   = analyzed.getParameters()

        orig_redir = ""
        orig_scope = "openid"
        for p in params:
            if p.getName() == "redirect_uri":
                orig_redir = p.getValue()
            if p.getName() == "scope":
                orig_scope = p.getValue()

        collab = e.collab_url or "https://oauthhunter-oob.example.com"
        host   = self.host

        e._log("Active tests: {} on {} ({} payloads)".format(
            self.vuln_type, host, len(payloads)))

        for tmpl in payloads:
            try:
                payload = tmpl
                payload = payload.replace("{redirect_uri}", orig_redir)
                payload = payload.replace("{host}",         host)
                payload = payload.replace("{path}",
                    str(analyzed.getUrl().getPath()))
                payload = payload.replace("{collab}",       collab)
                payload = payload.replace("{scope}",        orig_scope)

                result  = self._fire(payload, params)
                SwingUtilities.invokeLater(AppendActiveResult(e, result))
                time.sleep(0.35)
            except Exception as ex:
                e._log("Payload error: " + str(ex))

        e._log("Active tests complete: " + self.vuln_type)

    TARGET_MAP = {
        "open_redirect_absolute":     ["redirect_uri"],
        "redirect_uri_prefix_bypass": ["redirect_uri"],
        "state_jwt_tamperable":       ["state"],
        "scope_escalation":           ["scope"],
        "redirect_param_injection":   REDIRECT_PARAMS,
        "saml_relaystate_redirect":   ["RelayState"],
        "interceptor_bypass":         ["next", "returnTo", "redirect", "goto"],
    }

    def _fire(self, payload, orig_params):
        e       = self.ext
        req     = self.original_msg.getRequest()
        inject  = self.TARGET_MAP.get(self.vuln_type, ["redirect_uri"])
        modified = req

        injected = False
        for p in orig_params:
            if p.getName() in inject:
                modified = e._helpers.updateParameter(
                    modified,
                    e._helpers.buildParameter(
                        p.getName(), payload, p.getType()))
                injected = True
                break

        if not injected:
            modified = e._helpers.addParameter(
                modified,
                e._helpers.buildParameter(inject[0], payload, 0))

        try:
            service  = self.original_msg.getHttpService()
            resp_msg = e._callbacks.makeHttpRequest(service, modified)
            resp     = resp_msg.getResponse()
            ar       = e._helpers.analyzeResponse(resp)
            status   = ar.getStatusCode()
            location = ""
            for h in ar.getHeaders():
                hs = str(h)
                if hs.lower().startswith("location:"):
                    location = hs[9:].strip()
                    break
            body = e._helpers.bytesToString(resp)[:600]
            return {
                "vuln_type": self.vuln_type,
                "payload":   payload[:60],
                "status":    status,
                "location":  location[:80],
                "success":   self._success(status, location, body),
                "timestamp": time.strftime("%H:%M:%S"),
            }
        except Exception as ex:
            return {
                "vuln_type": self.vuln_type,
                "payload":   payload[:60],
                "status":    0,
                "location":  str(ex)[:60],
                "success":   False,
                "timestamp": time.strftime("%H:%M:%S"),
            }

    def _success(self, status, location, body):
        vt = self.vuln_type
        if vt in ("open_redirect_absolute", "redirect_uri_prefix_bypass"):
            return ("evil.com" in location or
                    "oauthhunter-oob" in location or
                    (status in (301, 302) and "error" not in location.lower()))
        if vt == "scope_escalation":
            return status in (200, 302) and "error" not in location.lower()
        if vt == "redirect_param_injection":
            return ("/admin" in location or
                    (status == 200 and "intercept" not in body.lower()))
        if vt == "interceptor_bypass":
            return status == 200 and "intercept" not in body.lower()
        if vt == "saml_relaystate_redirect":
            return "evil.com" in location or "/admin" in location
        return status not in (400, 401, 403, 500)


# ── OAuth Flow tracker ────────────────────────
class OAuthFlow(object):
    def __init__(self, host):
        self.host          = host
        self.requests      = []
        self.client_ids    = set()
        self.scopes        = set()
        self.redirect_uris = set()
        self.state_values  = []
        self.has_pkce      = False
        self.has_saml      = False
        self.has_wsfed     = False
        self.flow_type     = "unknown"
        self.findings      = []

    def to_dict(self):
        return {
            "host":          self.host,
            "flow_type":     self.flow_type,
            "client_ids":    list(self.client_ids),
            "scopes":        list(self.scopes),
            "redirect_uris": list(self.redirect_uris),
            "states_seen":   len(self.state_values),
            "pkce":          self.has_pkce,
            "saml":          self.has_saml,
            "wsfed":         self.has_wsfed,
            "requests":      len(self.requests),
            "findings":      len(self.findings),
        }


# ── Main extension class ──────────────────────
class BurpExtender(IBurpExtender, IHttpListener, ITab, IExtensionStateListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks   = callbacks
        self._helpers     = callbacks.getHelpers()
        callbacks.setExtensionName("OAuthHunter")
        callbacks.registerHttpListener(self)
        callbacks.registerExtensionStateListener(self)

        self.flows        = {}
        self.all_findings = []
        self.collab_url   = ""
        self.scope_filter = []
        self._paused      = False

        SwingUtilities.invokeLater(BuildUI(self))
        callbacks.addSuiteTab(self)
        print("[OAuthHunter] Loaded. Monitoring OAuth/SAML/OIDC traffic.")

    def getTabCaption(self):
        return "OAuthHunter"

    def getUiComponent(self):
        return self._main_panel

    def extensionUnloaded(self):
        print("[OAuthHunter] Unloaded.")

    # ── HTTP listener ─────────────────────────
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if self._paused:
            return
        try:
            if messageIsRequest:
                self._on_request(messageInfo)
            else:
                self._on_response(messageInfo)
        except Exception:
            pass

    def _on_request(self, msg):
        analyzed = self._helpers.analyzeRequest(msg)
        url      = analyzed.getUrl()
        host     = str(url.getHost())
        path     = str(url.getPath())
        params   = analyzed.getParameters()

        if self.scope_filter:
            if not any(h in host for h in self.scope_filter):
                return

        param_map = {}
        for p in params:
            param_map[str(p.getName())] = str(p.getValue())

        is_oauth = (any(k in param_map for k in OAUTH_PARAMS) or
                    any(seg in path     for seg in OAUTH_PATHS))
        if not is_oauth:
            return

        if host not in self.flows:
            self.flows[host] = OAuthFlow(host)
        flow = self.flows[host]

        flow.requests.append({
            "method": str(analyzed.getMethod()),
            "path":   path,
            "time":   time.strftime("%H:%M:%S"),
        })

        if "client_id"      in param_map: flow.client_ids.add(param_map["client_id"])
        if "scope"          in param_map: flow.scopes.add(param_map["scope"])
        if "redirect_uri"   in param_map: flow.redirect_uris.add(param_map["redirect_uri"])
        if "state"          in param_map: flow.state_values.append(param_map["state"])
        if "code_challenge" in param_map: flow.has_pkce = True
        if "SAMLRequest" in param_map or "SAMLResponse" in param_map:
            flow.has_saml  = True
            flow.flow_type = "saml"
        if "wresult" in param_map:
            flow.has_wsfed = True
            flow.flow_type = "wsfed"

        rt = param_map.get("response_type", "")
        if "token" in rt and "code" not in rt:
            flow.flow_type = "oauth2_implicit"
            self._add_finding(host, "implicit_flow", path, param_map, msg)
        elif "code" in rt:
            flow.flow_type = "oauth2_pkce" if flow.has_pkce else "oauth2_code"

        # ── Passive checks ──
        if "response_type" in param_map and "state" not in param_map:
            self._add_finding(host, "state_missing", path, param_map, msg)

        if "state" in param_map:
            s = param_map["state"]
            if len(s) < 8 or s.isdigit():
                self._add_finding(host, "state_predictable", path,
                                  {"state": s}, msg)
            decoded = self._decode_jwt(s)
            if decoded:
                if any(k in str(decoded)
                       for k in ["returnTo", "redirect", "next", "url"]):
                    self._add_finding(host, "state_jwt_tamperable", path,
                                      {"claims": str(decoded)[:300]}, msg,
                                      confidence="Firm")

        if param_map.get("response_type") == "code" and not flow.has_pkce:
            self._add_finding(host, "pkce_missing", path, param_map, msg)

        for rp in REDIRECT_PARAMS:
            if rp in param_map:
                val = param_map[rp]
                if val.startswith("http") or val.startswith("//"):
                    self._add_finding(host, "open_redirect_absolute",
                                      path, {rp: val}, msg)
                else:
                    self._add_finding(host, "redirect_param_injection",
                                      path, {rp: val}, msg,
                                      confidence="Tentative")

        if "RelayState" in param_map:
            rs = param_map["RelayState"]
            if rs.startswith("http") or "/" in rs:
                self._add_finding(host, "saml_relaystate_redirect",
                                  path, {"RelayState": rs}, msg)

        if any(x in path for x in ["interceptor", "intercept", "convert",
                                    "force", "landing", "post-login"]):
            self._add_finding(host, "interceptor_bypass", path,
                              param_map, msg, confidence="Tentative")

        SwingUtilities.invokeLater(RefreshFlowTree(self, host, flow))

    def _on_response(self, msg):
        analyzed_req  = self._helpers.analyzeRequest(msg)
        analyzed_resp = self._helpers.analyzeResponse(msg.getResponse())
        host   = str(analyzed_req.getUrl().getHost())
        path   = str(analyzed_req.getUrl().getPath())

        if self.scope_filter:
            if not any(h in host for h in self.scope_filter):
                return

        location = ""
        for h in analyzed_resp.getHeaders():
            hs = str(h)
            if hs.lower().startswith("location:"):
                location = hs[9:].strip()
            if hs.lower().startswith("set-cookie:"):
                self._check_cookie(host, path, hs, msg)

        if location:
            if "access_token=" in location or "id_token=" in location:
                self._add_finding(host, "token_in_url", path,
                                  {"location": location[:100]}, msg)
            if ("error=unauthorized_client" in location or
                    "error_description=" in location):
                self._add_finding(host, "error_info_disclosure", path,
                                  {"location": location[:200]}, msg)
                if "not in the list" in location or "mismatch" in location.lower():
                    self._add_finding(host, "redirect_uri_prefix_bypass",
                                      "Whitelist exposed in error response",
                                      {"error_location": location[:300]},
                                      msg, confidence="Firm")

    def _check_cookie(self, host, path, header, msg):
        parts = header[11:].strip()
        name  = parts.split("=")[0].strip().lower()
        low   = parts.lower()
        sensitive = ["auth0", "auth0_compat", "state", "session", "token",
                     "g2g", "eg2g", "returnto", "q2gexpiry", "access_token"]
        if name in sensitive:
            missing = []
            if "httponly" not in low: missing.append("HttpOnly")
            if "secure"   not in low: missing.append("Secure")
            if "samesite" not in low: missing.append("SameSite")
            if missing:
                self._add_finding(
                    host, "cookie_no_flags", path,
                    {"cookie": name, "missing": ", ".join(missing)},
                    msg, confidence="Certain")

    # ── Findings ──────────────────────────────
    def _add_finding(self, host, vuln_type, path, params,
                     msg, confidence="Certain"):
        for f in self.all_findings:
            if (f["host"] == host and
                    f["vuln_type"] == vuln_type and
                    f["path"] == path):
                return

        check = VULN_CHECKS.get(vuln_type, {})
        finding = {
            "host":        host,
            "vuln_type":   vuln_type,
            "name":        check.get("name", vuln_type),
            "severity":    check.get("severity", "INFO"),
            "cwe":         check.get("cwe", ""),
            "description": check.get("description", ""),
            "path":        path,
            "params":      params,
            "confidence":  confidence,
            "messageInfo": msg,
            "timestamp":   time.strftime("%H:%M:%S"),
        }
        self.all_findings.append(finding)
        if host in self.flows:
            self.flows[host].findings.append(finding)

        self._log("[{}] {} on {}{}".format(
            finding["severity"], finding["name"], host, path))
        SwingUtilities.invokeLater(RefreshFindingsTable(self))

    # ── Active tests ──────────────────────────
    def launch_active_tests(self, host, vuln_type, original_msg):
        from java.lang import Thread as JThread
        t = JThread(ActiveTestRunner(self, host, vuln_type, original_msg))
        t.setDaemon(True)
        t.start()

    # ── Helpers ───────────────────────────────
    def _decode_jwt(self, token):
        parts = str(token).split(".")
        if len(parts) < 2:
            return None
        try:
            seg    = parts[1]
            padded = seg + "=" * (4 - len(seg) % 4)
            return json.loads(base64.urlsafe_b64decode(padded))
        except Exception:
            return None

    def _log(self, msg):
        line = "[{}] {}\n".format(time.strftime("%H:%M:%S"), str(msg))
        SwingUtilities.invokeLater(AppendLog(self, line))


# ── UI builder ────────────────────────────────
class BuildUI(Runnable):
    def __init__(self, ext):
        self.ext = ext

    def run(self):
        e    = self.ext
        main = JPanel(BorderLayout())
        main.setBackground(C_BG)
        e._main_panel = main

        tabs = JTabbedPane()
        tabs.setBackground(C_SURFACE)
        tabs.setForeground(C_TEXT)
        tabs.setFont(Font("Monospaced", Font.BOLD, 12))
        e._tabs = tabs

        tabs.addTab("Findings",     self._findings_tab())
        tabs.addTab("Flow Map",     self._flow_tab())
        tabs.addTab("Active Tests", self._active_tab())
        tabs.addTab("Payload Lib",  self._payload_tab())
        tabs.addTab("Settings",     self._settings_tab())
        tabs.addTab("Log",          self._log_tab())

        main.add(self._header(), BorderLayout.NORTH)
        main.add(tabs, BorderLayout.CENTER)

    # ── Header bar ────────────────────────────
    def _header(self):
        e = self.ext
        p = JPanel(BorderLayout())
        p.setBackground(C_SURFACE)
        p.setBorder(BorderFactory.createMatteBorder(0, 0, 2, 0, C_ACCENT))

        lbl = JLabel("  OAuthHunter  -  Generic OAuth / OIDC / SAML Scanner")
        lbl.setFont(Font("Monospaced", Font.BOLD, 13))
        lbl.setForeground(C_ACCENT)

        btns = JPanel(FlowLayout(FlowLayout.RIGHT, 6, 4))
        btns.setBackground(C_SURFACE)

        pause_btn  = self._btn("Pause",       C_YELLOW)
        clear_btn  = self._btn("Clear All",   C_MUTED)
        export_btn = self._btn("Export JSON", C_GREEN)

        pause_btn.addActionListener(PauseAction(e, pause_btn))
        clear_btn.addActionListener(ClearAction(e))
        export_btn.addActionListener(ExportAction(e))

        btns.add(pause_btn)
        btns.add(clear_btn)
        btns.add(export_btn)

        p.add(lbl, BorderLayout.WEST)
        p.add(btns, BorderLayout.EAST)
        return p

    # ── Findings tab ──────────────────────────
    def _findings_tab(self):
        e    = self.ext
        p    = JPanel(BorderLayout())
        p.setBackground(C_BG)

        cols  = ["Time", "Host", "Severity", "Vulnerability",
                  "Path", "Confidence", "CWE"]
        model = ReadOnlyTableModel(cols, 0)
        e._findings_model = model

        table = self._table(model)
        sev_r = SeverityRenderer()
        for i in range(len(cols)):
            table.getColumnModel().getColumn(i).setCellRenderer(sev_r)

        widths = [65, 160, 75, 270, 180, 75, 80]
        for i, w in enumerate(widths):
            table.getColumnModel().getColumn(i).setPreferredWidth(w)

        detail = self._textarea()
        table.addMouseListener(FindingSelectListener(e, table, detail))

        attack_btn = self._btn("Launch Active Tests for Selected", C_RED)
        attack_btn.addActionListener(AttackAction(e, table))

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT,
                           JScrollPane(table), JScrollPane(detail))
        split.setResizeWeight(0.58)
        split.setBackground(C_BG)

        south = JPanel(BorderLayout())
        south.setBackground(C_BG)
        south.add(attack_btn, BorderLayout.EAST)

        p.add(split,  BorderLayout.CENTER)
        p.add(south,  BorderLayout.SOUTH)
        return p

    # ── Flow map tab ──────────────────────────
    def _flow_tab(self):
        e = self.ext
        p = JPanel(BorderLayout())
        p.setBackground(C_BG)

        root       = DefaultMutableTreeNode("Detected Flows")
        tree_model = DefaultTreeModel(root)
        tree       = JTree(tree_model)

        e._flow_root       = root
        e._flow_tree_model = tree_model
        e._flow_tree       = tree

        tree.setBackground(C_SURFACE)
        tree.setForeground(C_TEXT)
        tree.setFont(Font("Monospaced", Font.PLAIN, 11))

        detail = self._textarea()
        tree.addMouseListener(TreeSelectListener(e, tree, detail))

        split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                           JScrollPane(tree), JScrollPane(detail))
        split.setResizeWeight(0.35)
        split.setBackground(C_BG)

        note = JLabel("  Browse any OAuth/SAML login - flows detected automatically")
        note.setFont(Font("Monospaced", Font.PLAIN, 11))
        note.setForeground(C_MUTED)

        p.add(note,  BorderLayout.NORTH)
        p.add(split, BorderLayout.CENTER)
        return p

    # ── Active tests tab ──────────────────────
    def _active_tab(self):
        e = self.ext
        p = JPanel(BorderLayout())
        p.setBackground(C_BG)

        cols  = ["Time", "Result", "Vuln Type", "Payload", "Status", "Location"]
        model = ReadOnlyTableModel(cols, 0)
        e._active_model = model

        table = self._table(model)
        res_r = ResultRenderer()
        for i in range(len(cols)):
            table.getColumnModel().getColumn(i).setCellRenderer(res_r)
        widths = [65, 50, 200, 260, 55, 260]
        for i, w in enumerate(widths):
            table.getColumnModel().getColumn(i).setPreferredWidth(w)

        note = JLabel(
            "  Select a finding in the Findings tab and click 'Launch Active Tests'")
        note.setFont(Font("Monospaced", Font.PLAIN, 11))
        note.setForeground(C_MUTED)

        p.add(note, BorderLayout.NORTH)
        p.add(JScrollPane(table), BorderLayout.CENTER)
        return p

    # ── Payload library tab ───────────────────
    def _payload_tab(self):
        p = JPanel(BorderLayout())
        p.setBackground(C_BG)

        btn_panel = JPanel()
        btn_panel.setLayout(BoxLayout(btn_panel, BoxLayout.Y_AXIS))
        btn_panel.setBackground(C_SURFACE)

        area = self._textarea()
        area.setEditable(True)
        area.setText("Select a vulnerability class on the left.")

        for vt in sorted(VULN_CHECKS.keys()):
            check    = VULN_CHECKS[vt]
            payloads = check.get("payloads", [])
            text = ("Vulnerability:  {}\n"
                    "Severity:       {}\n"
                    "CWE:            {}\n\n"
                    "Description:\n{}\n\n"
                    "Payloads:\n{}").format(
                check["name"], check["severity"], check["cwe"],
                check["description"],
                "\n".join(payloads) if payloads
                else "(passive detection only)"
            )
            btn = self._btn(check["name"][:50],
                            SEVERITY_COLORS.get(check["severity"], C_TEXT))
            btn.setMaximumSize(Dimension(410, 26))
            btn.setHorizontalAlignment(SwingConstants.LEFT)
            btn.addActionListener(PayloadBtnAction(text, area))
            btn_panel.add(btn)

        split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                           JScrollPane(btn_panel), JScrollPane(area))
        split.setResizeWeight(0.38)
        split.setBackground(C_BG)

        note = JLabel("  Click a class to view payloads. Payloads are editable.")
        note.setFont(Font("Monospaced", Font.PLAIN, 11))
        note.setForeground(C_MUTED)

        p.add(note,  BorderLayout.NORTH)
        p.add(split, BorderLayout.CENTER)
        return p

    # ── Settings tab ──────────────────────────
    def _settings_tab(self):
        e = self.ext
        p = JPanel(GridBagLayout())
        p.setBackground(C_BG)

        gbc          = GridBagConstraints()
        gbc.insets   = Insets(10, 14, 10, 14)
        gbc.fill     = GridBagConstraints.HORIZONTAL

        collab_field = JTextField(
            e.collab_url or "https://your-collaborator.burpcollaborator.net", 42)
        collab_field.setBackground(C_SURFACE)
        collab_field.setForeground(C_TEXT)
        collab_field.setFont(Font("Monospaced", Font.PLAIN, 11))

        scope_field = JTextField("", 42)
        scope_field.setBackground(C_SURFACE)
        scope_field.setForeground(C_TEXT)
        scope_field.setFont(Font("Monospaced", Font.PLAIN, 11))

        save_btn = self._btn("Save Settings", C_GREEN)
        save_btn.addActionListener(
            SaveSettingsAction(e, collab_field, scope_field))

        fields = [
            ("Collaborator / OOB URL:", collab_field),
            ("Scope filter (comma-sep hosts, blank=all):", scope_field),
        ]
        for i, (label, widget) in enumerate(fields):
            gbc.gridx, gbc.gridy, gbc.weightx = 0, i, 0
            lbl = JLabel(label)
            lbl.setFont(Font("Monospaced", Font.BOLD, 11))
            lbl.setForeground(C_ACCENT)
            p.add(lbl, gbc)
            gbc.gridx, gbc.weightx = 1, 1.0
            p.add(widget, gbc)

        gbc.gridx, gbc.gridy, gbc.weightx = 1, len(fields), 0
        p.add(save_btn, gbc)

        info = self._textarea()
        info.setEditable(False)
        info.setForeground(C_MUTED)
        info.setText(
            "\nHow to use OAuthHunter:\n\n"
            "1. Browse through any OAuth/SAML login flow in your browser.\n"
            "   OAuthHunter auto-detects the flow - no config required.\n\n"
            "2. Go to Findings tab to see all detected issues.\n\n"
            "3. Select a finding and click 'Launch Active Tests' to fire\n"
            "   real payloads against that vulnerability class.\n\n"
            "4. Results appear live in the Active Tests tab.\n\n"
            "5. Use Export JSON to save findings for your report.\n\n"
            "Supported protocols:\n"
            "  - OAuth 2.0 (auth code, implicit, hybrid)\n"
            "  - OIDC with PKCE detection\n"
            "  - SAML 2.0 (SP and IdP initiated)\n"
            "  - WS-Federation\n"
            "  - Custom interceptor / post-login redirect patterns\n\n"
            "Export path: /tmp/oauthhunter_findings.json\n"
        )
        gbc.gridx, gbc.gridy      = 0, len(fields) + 1
        gbc.gridwidth, gbc.weightx = 2, 1.0
        gbc.weighty, gbc.fill      = 1.0, GridBagConstraints.BOTH
        p.add(JScrollPane(info), gbc)
        return p

    # ── Log tab ───────────────────────────────
    def _log_tab(self):
        e = self.ext
        p = JPanel(BorderLayout())
        p.setBackground(C_BG)

        area = JTextArea()
        area.setBackground(C_BG)
        area.setForeground(C_MUTED)
        area.setFont(Font("Monospaced", Font.PLAIN, 10))
        area.setEditable(False)
        area.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8))
        e._log_area = area

        clear_btn = self._btn("Clear Log", C_MUTED)
        clear_btn.addActionListener(ClearLogAction(area))

        p.add(JScrollPane(area), BorderLayout.CENTER)
        p.add(clear_btn,         BorderLayout.SOUTH)
        return p

    # ── Widget helpers ────────────────────────
    def _btn(self, txt, fg=C_TEXT):
        b = JButton(txt)
        b.setFont(Font("Monospaced", Font.PLAIN, 11))
        b.setBackground(C_SURFACE)
        b.setForeground(fg)
        b.setFocusPainted(False)
        return b

    def _table(self, model):
        t = JTable(model)
        t.setBackground(C_SURFACE)
        t.setForeground(C_TEXT)
        t.setGridColor(C_BORDER)
        t.setSelectionBackground(C_ACCENT.darker())
        t.setFont(Font("Monospaced", Font.PLAIN, 11))
        t.getTableHeader().setBackground(C_BG)
        t.getTableHeader().setForeground(C_ACCENT)
        t.getTableHeader().setFont(Font("Monospaced", Font.BOLD, 11))
        t.setRowHeight(22)
        t.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)
        return t

    def _textarea(self):
        a = JTextArea()
        a.setBackground(C_BG)
        a.setForeground(C_TEXT)
        a.setFont(Font("Monospaced", Font.PLAIN, 11))
        a.setEditable(False)
        a.setLineWrap(True)
        a.setWrapStyleWord(True)
        a.setBorder(BorderFactory.createEmptyBorder(8, 10, 8, 10))
        return a
