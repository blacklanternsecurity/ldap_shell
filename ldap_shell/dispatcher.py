import logging
import shlex
import string

from ldap_shell.utils.module_loader import ModuleLoader


class CommandDispatcher:
    def __init__(self, modules, domain_dumper, client):
        self.modules = modules
        self.domain_dumper = domain_dumper
        self.client = client
        self.identchars = string.ascii_letters + string.digits + '_'
        self.log = logging.getLogger('ldap-shell')

    def parseline(self, line):
        line = line.strip()
        if not line:
            return None, None, line
        elif line[0] == '?':
            line = 'help ' + line[1:]
        i, n = 0, len(line)
        while i < n and line[i] in self.identchars:
            i = i + 1
        cmd, arg = line[:i], line[i:].strip()
        return cmd, arg, line

    def _parse_arg_string(self, module_name: str, arg_string: str) -> dict:
        args_dict = {}
        try:
            args = shlex.split(arg_string)
        except ValueError as e:
            print(f"Warning: {e}")
            args = arg_string.strip().split()

        for i, value in enumerate(args):
            if i >= len(self.modules[module_name].get_arguments()):
                break
            arg_name = self.modules[module_name].get_arguments()[i].name
            args_dict[arg_name] = value
        return args_dict

    def parse_module_args(self, module_name: str, arg_string: str) -> dict:
        if module_name not in self.modules:
            raise ValueError(f"Module {module_name} not found")
        return self._parse_arg_string(module_name, arg_string)

    def check_args_exist(self, module_name: str, args_dict: dict) -> bool:
        arguments = self.modules[module_name].get_arguments()
        for arg in arguments:
            if arg.name not in args_dict and arg.required:
                return False
        return True

    def execute_module(self, module_name: str, args_dict: dict):
        module = self.modules[module_name](
            args_dict,
            self.domain_dumper,
            self.client,
            logging.getLogger('ldap-shell')
        )
        return module()

    def onecmd(self, line):
        cmd, arg_string, _ = self.parseline(line)
        if cmd is None or cmd == '':
            return None

        if cmd in self.modules:
            try:
                args_dict = self.parse_module_args(cmd, arg_string)
                if not self.check_args_exist(cmd, args_dict):
                    print(f'*** Missing required arguments for {cmd}. Use `help {cmd}` to see available arguments.')
                    return None
                return self.execute_module(cmd, args_dict)
            except ValueError as e:
                print(f"Error: {e}")
                import traceback
                print("Traceback:")
                print(traceback.format_exc())
        else:
            print(f'Module {cmd} not found')
        return None
