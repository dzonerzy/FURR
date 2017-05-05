"""
FURR HTTP fuzzer based on radamsa and zzuf.
MIT License
Copyright (c) 2016 Daniele Linguaglossa <danielelinguaglossa@gmail.com>
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import re
import sys
import random
import subprocess
from burp import ITab
from burp import IBurpExtender
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadGenerator
from javax.swing import JLabel, JTextField, JOptionPane, JTabbedPane, JPanel, JButton, JCheckBox
from java.awt import GridBagLayout, GridBagConstraints

class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory, ITab):
    name = "FURR - Fuzz yoUR Request"
    args = []
    zzuf = ""
    radamsa = ""
    _jTabbedPane = JTabbedPane()
    _jPanel = JPanel()
    _jAboutPanel = JPanel()
    _jPanelConstraints = GridBagConstraints()
    aboutText = "<h1>How-to</h1><br>" \
                "<pre>In order to use FURR you MUST install zzuf & radamsa from source using: <br>" \
                "<b>git clone https://github.com/samhocevar/zzuf.git && make && sudo make install</b><br>" \
                "<b>git clone https://github.com/aoh/radamsa.git && make && sudo make install</b><br>" \
                "Once done zzuf and radamsa should be in your PATH so try:<br>" \
                "<b>echo 'fuzzme!' | zuff -r 0.01 -s 1</b><br>" \
                "<b>echo 'fuzzme!' | radamsa</b><br>" \
                "If you get a different result from the original 'fuzzme' than you're ready to go!</pre><br><br>" \
                "<h1>About me</h1><br>" \
                "I'm a security expert working @ Consulthink S.p.A. passionate about fuzzing and exploitation!<br>" \
                "<h1>About FURR</h1><br>" \
                "FURR is still a 'work in progress' tool it will be upgraded every time is possible so stay tuned!<br><br>" \
                "<center><h2>Happy fuzzing!</h2></center>"

    def which(self, bin):
        find_bin = subprocess.Popen(["/usr/bin/which", bin],stdout=subprocess.PIPE)
        find_bin.wait()
        binary=find_bin.stdout.read().replace("\n", "").replace("\r", "")
        if not binary:
            sys.stderr.write("Unable to find {0} in path! Please symlink {1} to /usr/local/bin/{2}".format(bin,bin,bin))
            return ""
        else:
            return binary

    def registerExtenderCallbacks(self, callbacks):
        self.zzuf = self.which("zzuf")
        self.radamsa = self.which("radamsa")
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName(self.name)
        callbacks.registerIntruderPayloadGeneratorFactory(self)
        callbacks.addSuiteTab(self)
        self.initPanelConfig()
        self._jTabbedPane.addTab("Configuration", self._jPanel)
        self._jTabbedPane.addTab("About", self._jAboutPanel)
        return

    def getUiComponent(self):
        return self._jTabbedPane

    def getTabCaption(self):
        return "FURR"

    def initPanelConfig(self):
        self._jPanel.setBounds(0, 0, 1000, 1000)
        self._jPanel.setLayout(GridBagLayout())

        self._jAboutPanel.setBounds(0, 0, 1000, 1000)
        self._jAboutPanel.setLayout(GridBagLayout())

        self._jLabelTitle = JLabel("<html><body><b><center>Fuzzing options</center></b><br></body></html>")
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 0
        self._jPanelConstraints.gridy = 0
        self._jPanel.add(self._jLabelTitle, self._jPanelConstraints)

        self._jCheckBoxMethod = JCheckBox("Request Method")
        self._jCheckBoxMethod.setSelected(True)
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 0
        self._jPanelConstraints.gridy = 1
        self._jPanel.add(self._jCheckBoxMethod, self._jPanelConstraints)

        self._jCheckBoxPath = JCheckBox("Request Path")
        self._jCheckBoxPath.setSelected(True)
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 0
        self._jPanelConstraints.gridy = 2
        self._jPanel.add(self._jCheckBoxPath, self._jPanelConstraints)

        self._jCheckBoxHTTP = JCheckBox("HTTP String")
        self._jCheckBoxHTTP.setSelected(True)
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 0
        self._jPanelConstraints.gridy = 3
        self._jPanel.add(self._jCheckBoxHTTP, self._jPanelConstraints)

        self._jCheckBoxHTTPver = JCheckBox("HTTP Version")
        self._jCheckBoxHTTPver.setSelected(True)
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 0
        self._jPanelConstraints.gridy = 4
        self._jPanel.add(self._jCheckBoxHTTPver, self._jPanelConstraints)

        self._jCheckBoxHeaderName = JCheckBox("Header Name")
        self._jCheckBoxHeaderName.setSelected(True)
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 0
        self._jPanelConstraints.gridy = 5
        self._jPanel.add(self._jCheckBoxHeaderName, self._jPanelConstraints)

        self._jCheckBoxHeaderValue = JCheckBox("Header Content")
        self._jCheckBoxHeaderValue.setSelected(True)
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 0
        self._jPanelConstraints.gridy = 6
        self._jPanel.add(self._jCheckBoxHeaderValue, self._jPanelConstraints)

        self._jCheckBoxBodyValue = JCheckBox("Body Content")
        self._jCheckBoxBodyValue.setSelected(True)
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 0
        self._jPanelConstraints.gridy = 7
        self._jPanel.add(self._jCheckBoxBodyValue, self._jPanelConstraints)

        self._jCheckBoxParamName = JCheckBox("Parameters Name")
        self._jCheckBoxParamName.setSelected(True)
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 0
        self._jPanelConstraints.gridy = 8
        self._jPanel.add(self._jCheckBoxParamName, self._jPanelConstraints)

        self._jCheckBoxParamValue = JCheckBox("Parameters Value")
        self._jCheckBoxParamValue.setSelected(True)
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 0
        self._jPanelConstraints.gridy = 9
        self._jPanel.add(self._jCheckBoxParamValue, self._jPanelConstraints)

        self._jCheckBoxAllRequest = JCheckBox("Entire Request")
        self._jCheckBoxAllRequest.setSelected(True)
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 0
        self._jPanelConstraints.gridy = 10
        self._jPanel.add(self._jCheckBoxAllRequest, self._jPanelConstraints)

        self._jLabelSpace = JLabel("<html><body><b><center>&nbsp;</center></b><br></body></html>")
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 0
        self._jPanelConstraints.gridy = 11
        self._jPanel.add(self._jLabelSpace, self._jPanelConstraints)

        self._jButtonSetCommandLine = JButton('Set Configuration', actionPerformed=self.setCommandLine)
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 0
        self._jPanelConstraints.gridy = 12
        self._jPanelConstraints.gridwidth = 2
        self._jPanel.add(self._jButtonSetCommandLine, self._jPanelConstraints)

        self._jButtonReset = JButton('Reset all', actionPerformed=self.resetAll)
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 0
        self._jPanelConstraints.gridy = 13
        self._jPanelConstraints.gridwidth = 2
        self._jPanel.add(self._jButtonReset, self._jPanelConstraints)

        self._jLabelAbout = JLabel("<html><body>%s</body></html>" % self.aboutText)
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 0
        self._jPanelConstraints.gridy = 0
        self._jAboutPanel.add(self._jLabelAbout, self._jPanelConstraints)

    def resetAll(self, event=None):
        self._jCheckBoxMethod.setSelected(True)
        self._jCheckBoxPath.setSelected(True)
        self._jCheckBoxHTTP.setSelected(True)
        self._jCheckBoxHTTPver.setSelected(True)
        self._jCheckBoxHeaderName.setSelected(True)
        self._jCheckBoxHeaderValue.setSelected(True)
        self._jCheckBoxBodyValue.setSelected(True)
        self._jCheckBoxParamName.setSelected(True)
        self._jCheckBoxParamValue.setSelected(True)
        self._jCheckBoxAllRequest.setSelected(True)

    def setCommandLine(self, event=None):
        method = self._jCheckBoxMethod.isSelected()
        path = self._jCheckBoxPath.isSelected()
        httpstring = self._jCheckBoxHTTP.isSelected()
        httpver = self._jCheckBoxHTTPver.isSelected()
        headername = self._jCheckBoxHeaderName.isSelected()
        headervalue = self._jCheckBoxHeaderValue.isSelected()
        bodyvalue = self._jCheckBoxBodyValue.isSelected()
        paramname = self._jCheckBoxParamName.isSelected()
        paramvalue = self._jCheckBoxParamValue.isSelected()
        allrequest = self._jCheckBoxAllRequest.isSelected()
        self.tokens = []
        if method:
            self.tokens.append(re.compile("^(POST|GET|HEAD|OPTIONS|DELETE|TRACE|PUT|UPDATE)",re.MULTILINE))
        if path:
            self.tokens.append(re.compile("^[A-Z]+\s(.*)\s+HTTP",re.MULTILINE))
        if httpstring:
            self.tokens.append(re.compile("\s(HTTP)",re.MULTILINE))
        if httpver:
            self.tokens.append(re.compile("HTTP/([0-9.]+)",re.MULTILINE))
        if headername:
            self.tokens.append(re.compile("(.*):\s", re.MULTILINE))
        if headervalue:
            self.tokens.append(re.compile(":\s(.*)", re.MULTILINE))
        if bodyvalue:
            self.tokens.append(re.compile("\r\n\r\n(.*)", re.MULTILINE))
        if paramname:
            self.tokens.append(re.compile("([A-Za-z0-9]+)=[\w\d%%.-_\\/\(\)\[\]\*]+", re.MULTILINE))
        if paramvalue:
            self.tokens.append(re.compile("[A-Za-z0-9]+=([\w\d%%.-_\\/\(\)\[\]\*]+)", re.MULTILINE))
        if allrequest:
            self.tokens.append(re.compile("([\d\D\w\W]+)",re.MULTILINE))
        JOptionPane.showMessageDialog(None, "Command line configured!")

    def getGeneratorName(self):
        return "ZZufler"

    def createNewInstance(self, attack):
        return HTTPFuzzer(self, attack, self.zzuf, self.radamsa, self.tokens)


class HTTPFuzzer(IIntruderPayloadGenerator):
    def __init__(self, extender, attack, zzuf, radamsa, tokens):
        self._tokens = tokens
        self._extender = extender
        self._helpers = extender._helpers
        self._attack = attack
        if zzuf:
            self.zzuf = zzuf
        else:
            self.zzuf = "/usr/local/bin/zzuf"
        if radamsa:
            self.radamsa = radamsa
        else:
            self.radamsa = "/usr/local/bin/radamsa"
        return

    def hasMorePayloads(self):
        return True

    def getNextPayload(self, current_payload):
        payload = "".join(chr(x) for x in current_payload)
        payload = self.fuzz_request(payload, self._tokens)
        return payload

    def reset(self):
        return

    def fuzz(self, data, maintain_length=True):
        p0 = subprocess.Popen(["/bin/echo", "-n", data], stdout=subprocess.PIPE)
        if maintain_length:
            p1 = subprocess.Popen([self.zzuf ,"-r", str(random.uniform(0.004, 0.25)), "-P", "\\r\\n", "-R",
                                   "\\x00-\\x1f\\x7f-\\xff"], stdin=p0.stdout, stdout=subprocess.PIPE)
            output = p1.stdout.read()
        else:
            p1 = subprocess.Popen([self.radamsa], stdin=p0.stdout, stdout=subprocess.PIPE)
            output = p1.stdout.read()
        return output

    def get_random_tokens(self, data, tokens):
        token_list = []
        matches = random.choice(tokens).finditer(data)
        for _ , match in enumerate(matches):
            for _ in match.groups():
                token_list.append((match.group(1), match.start(1), match.end(1)))
        return token_list , random.randint(1, len(token_list))

    def fuzz_request(self, data, tokens):
        tokens, changes = self.get_random_tokens(data, tokens)
        for _ in range(changes):
            try:
                extract = random.choice(tokens)
                tokens.remove(extract)
                original = extract[0]
                start = extract[1]
                end = extract[2]
                fuzzed = self.fuzz(original, random.choice([True, False]))
                data = data[0:start] + fuzzed + data[end:]
            except:
                return self.fuzz(data, random.choice([True, False]))
        return data
