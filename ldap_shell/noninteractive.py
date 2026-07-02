import sys

from ldap_shell.dispatcher import CommandDispatcher
from ldap_shell.utils.module_loader import ModuleLoader


class NonInteractiveShell:
    def __init__(self, domain_dumper, client):
        self.modules = ModuleLoader.load_modules()
        self.dispatcher = CommandDispatcher(self.modules, domain_dumper, client)

    def run(self):
        for line in sys.stdin:
            line = line.strip()
            if line == 'exit':
                break
            if line:
                self.dispatcher.onecmd(line)
