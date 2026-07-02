import asyncio
import logging
import shlex
import sys

from rich.text import Text
from textual import events, work
from textual.app import App, ComposeResult
from textual.containers import Horizontal
from textual.screen import ModalScreen
from textual.widgets import Footer, Input, OptionList, RichLog, Static
from textual.widgets.option_list import Option

from ldap_shell.completers import CompleterFactory
from ldap_shell.completers.base import CompletionItem
from ldap_shell.dispatcher import CommandDispatcher
from ldap_shell.utils import history
from ldap_shell.utils.module_loader import ModuleLoader


class TUIWriter:
    def __init__(self, richlog, app):
        self.richlog = richlog
        self.app = app
        self._line_buffer = ""

    def write(self, text):
        self._line_buffer += text
        while '\n' in self._line_buffer:
            line, self._line_buffer = self._line_buffer.split('\n', 1)
            if line:
                try:
                    rich_text = Text.from_ansi(line)
                    self.app.call_from_thread(self.richlog.write, rich_text)
                except RuntimeError:
                    pass

    def flush(self):
        if self._line_buffer:
            try:
                rich_text = Text.from_ansi(self._line_buffer)
                self.app.call_from_thread(self.richlog.write, rich_text)
            except RuntimeError:
                pass
            self._line_buffer = ""


class OutputCapture:
    def __init__(self, richlog, app):
        self.richlog = richlog
        self.app = app
        self._old_stdout = None

    def __enter__(self):
        self._old_stdout = sys.stdout
        sys.stdout = TUIWriter(self.richlog, self.app)
        return self

    def __exit__(self, *args):
        sys.stdout.flush()
        sys.stdout = self._old_stdout


class RichLogHandler(logging.Handler):
    def __init__(self, richlog, app):
        super().__init__()
        self.richlog = richlog
        self._app = app

    def emit(self, record):
        try:
            msg = self.format(record)
            rich_text = Text.from_ansi(msg)
            self._app.call_from_thread(self.richlog.write, rich_text)
        except RuntimeError:
            pass
        except Exception:
            pass


class PasswordScreen(ModalScreen[str]):
    CSS = """
    PasswordScreen {
        align: center middle;
    }
    #password-dialog {
        width: 50;
        height: 7;
        border: thick $accent;
        background: $surface;
        padding: 1 2;
    }
    #password-label {
        margin-bottom: 1;
    }
    """

    def compose(self) -> ComposeResult:
        with Horizontal(id="password-dialog"):
            yield Static("Password:", id="password-label")
            yield Input(password=True, id="password-input")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.dismiss(event.value)

    def on_key(self, event: events.Key) -> None:
        if event.key == "escape":
            self.dismiss("")


class LdapShellApp(App):
    CSS = """
    #output {
        height: 1fr;
        border: solid green;
        scrollbar-size: 1 1;
    }
    #bottom-bar {
        height: 3;
        dock: bottom;
        padding: 0 1;
    }
    #prompt-label {
        width: auto;
        color: $accent;
        padding: 1 0;
    }
    #command-input {
        width: 1fr;
    }
    #autocomplete {
        layer: overlay;
        dock: bottom;
        offset: 0 -3;
        max-height: 12;
        display: none;
        border: solid $accent;
        background: $surface;
    }
    """

    BINDINGS = [
        ("escape", "dismiss_autocomplete", "Dismiss"),
    ]
    LAYERS = ["default", "overlay"]

    def __init__(self, domain_dumper, client):
        super().__init__()
        self.domain_dumper = domain_dumper
        self.client = client
        self.prompt_text = f'{client.user.split(chr(92))[1]}# '
        self.modules = ModuleLoader.load_modules()
        self.cmd_history = history
        self._history_index = len(history)
        self._completions: list[CompletionItem] = []
        self._saved_input = ""
        self.dispatcher = CommandDispatcher(self.modules, domain_dumper, client)

    def compose(self) -> ComposeResult:
        yield RichLog(id="output", wrap=True, markup=True)
        yield OptionList(id="autocomplete")
        with Horizontal(id="bottom-bar"):
            yield Static(self.prompt_text, id="prompt-label")
            yield Input(placeholder="Type a command...", id="command-input")
        yield Footer()

    def on_mount(self) -> None:
        output = self.query_one("#output", RichLog)

        rich_handler = RichLogHandler(output, self)
        rich_handler.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))

        logger = logging.getLogger('ldap-shell')
        for handler in logger.handlers[:]:
            if isinstance(handler, logging.StreamHandler):
                logger.removeHandler(handler)
        logger.addHandler(rich_handler)
        logger.propagate = False

        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            if isinstance(handler, logging.StreamHandler) and getattr(handler, 'stream', None) is sys.stdout:
                root_logger.removeHandler(handler)

        output.write(Text.from_ansi("\033[1;32mLDAP Shell v2.1.0\033[0m"))
        output.write(f"Connected as {self.client.user}")
        output.write("Type 'help' for available commands, 'exit' to quit.\n")

        self.query_one("#command-input", Input).focus()

    def _get_module_completions(self, word: str) -> list[CompletionItem]:
        completions = []
        word_lower = word.lower()
        for module_name, module_class in self.modules.items():
            if word_lower in module_name.lower():
                completions.append(CompletionItem(
                    text=module_name,
                    display=module_name,
                    display_meta=module_class.__doc__ or "",
                    start_position=-len(word)
                ))
        completions.sort(key=lambda c: (not c.text.startswith(word), c.text))
        return completions

    def _get_completions(self, text: str) -> list[CompletionItem]:
        try:
            words = shlex.split(text)
        except ValueError:
            words = shlex.split(text + '"')
        if text.endswith(' '):
            words.append('')

        if len(words) <= 1 and not text.endswith(' '):
            word = words[0] if words else ''
            return self._get_module_completions(word)

        module_name = words[0]
        if module_name not in self.modules:
            return []

        module_class = self.modules[module_name]
        arguments = module_class.get_arguments()
        current_arg_index = max(len(words) - 2, 0)

        if current_arg_index >= len(arguments):
            return []

        current_arg = arguments[current_arg_index]
        completer = CompleterFactory.create_completer(
            current_arg.arg_type, self.client, self.domain_dumper
        )
        if completer:
            current_word = words[-1] if words else ''
            return list(completer.get_completions(text, current_word))
        return []

    def _apply_completion(self, input_widget: Input, completion: CompletionItem) -> None:
        text = input_widget.value
        words = text.split()
        if len(words) <= 1 and not text.endswith(' '):
            input_widget.value = completion.text + ' '
        else:
            cursor = len(text)
            start = cursor + completion.start_position
            input_widget.value = text[:start] + completion.text
        input_widget.cursor_position = len(input_widget.value)

    def _show_completions(self, completions: list[CompletionItem]) -> None:
        dropdown = self.query_one("#autocomplete", OptionList)
        dropdown.clear_options()
        self._completions = completions
        for item in completions[:20]:
            label = item.display or item.text
            if item.display_meta:
                label = f"{label}  ({item.display_meta})"
            dropdown.add_option(Option(label))
        if completions:
            dropdown.styles.display = "block"
            dropdown.highlighted = 0
        else:
            dropdown.styles.display = "none"

    def _hide_autocomplete(self) -> None:
        dropdown = self.query_one("#autocomplete", OptionList)
        dropdown.styles.display = "none"
        self._completions = []

    def action_dismiss_autocomplete(self) -> None:
        self._hide_autocomplete()

    @work(exclusive=True, thread=True, group="completions")
    def _fetch_completions(self, text: str) -> None:
        completions = self._get_completions(text)
        if len(completions) == 1:
            self.call_from_thread(self._apply_completion,
                                  self.query_one("#command-input", Input),
                                  completions[0])
        elif completions:
            self.call_from_thread(self._show_completions, completions)

    def on_key(self, event: events.Key) -> None:
        input_widget = self.query_one("#command-input", Input)
        dropdown = self.query_one("#autocomplete", OptionList)
        dropdown_visible = str(dropdown.styles.display) != "none"

        if event.key == "up":
            if dropdown_visible:
                dropdown.action_cursor_up()
            else:
                entries = self.cmd_history.get_strings()
                if entries and self._history_index > 0:
                    if self._history_index == len(entries):
                        self._saved_input = input_widget.value
                    self._history_index -= 1
                    input_widget.value = entries[self._history_index]
                    input_widget.cursor_position = len(input_widget.value)
            event.prevent_default()
            event.stop()

        elif event.key == "down":
            if dropdown_visible:
                dropdown.action_cursor_down()
            else:
                entries = self.cmd_history.get_strings()
                if self._history_index < len(entries) - 1:
                    self._history_index += 1
                    input_widget.value = entries[self._history_index]
                    input_widget.cursor_position = len(input_widget.value)
                elif self._history_index < len(entries):
                    self._history_index = len(entries)
                    input_widget.value = self._saved_input
                    input_widget.cursor_position = len(input_widget.value)
            event.prevent_default()
            event.stop()

        elif event.key == "tab":
            if dropdown_visible:
                dropdown.action_cursor_down()
            else:
                text = input_widget.value
                try:
                    words = shlex.split(text)
                except ValueError:
                    words = shlex.split(text + '"')
                is_first_word = len(words) <= 1 and not text.endswith(' ')
                if is_first_word:
                    word = words[0] if words else ''
                    completions = self._get_module_completions(word)
                    if len(completions) == 1:
                        self._apply_completion(input_widget, completions[0])
                    elif completions:
                        self._show_completions(completions)
                else:
                    self._fetch_completions(text)
            event.prevent_default()
            event.stop()

        elif event.key == "enter":
            if dropdown_visible:
                if self._completions and dropdown.highlighted is not None:
                    idx = dropdown.highlighted
                    if idx < len(self._completions):
                        self._apply_completion(input_widget, self._completions[idx])
                self._hide_autocomplete()
            else:
                line = input_widget.value
                input_widget.value = ""
                self._hide_autocomplete()
                self._execute_command(line)
            event.prevent_default()
            event.stop()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option_list.id == "autocomplete":
            idx = event.option_index
            if idx < len(self._completions):
                input_widget = self.query_one("#command-input", Input)
                self._apply_completion(input_widget, self._completions[idx])
            self._hide_autocomplete()

    def _execute_command(self, line: str) -> None:
        line = line.strip()
        if not line:
            return
        if line == 'exit':
            self.exit()
            return

        self.cmd_history.append(line)
        self._history_index = len(self.cmd_history)

        output = self.query_one("#output", RichLog)
        output.write(Text.from_ansi(f"\033[1m{self.prompt_text}\033[0m{line}"))

        cmd, arg_string, _ = self.dispatcher.parseline(line)
        if cmd == 'switch_user' and cmd in self.modules:
            try:
                args_dict = self.dispatcher.parse_module_args(cmd, arg_string)
            except ValueError:
                args_dict = {}
            if 'password' not in args_dict or not args_dict.get('password'):
                asyncio.get_running_loop().create_task(
                    self._prompt_password_and_run(cmd, args_dict)
                )
                return

        self._run_module(line)

    async def _prompt_password_and_run(self, cmd: str, args_dict: dict) -> None:
        password = await self.push_screen_wait(PasswordScreen())
        if password:
            args_dict['password'] = password
            line = f"{cmd} {args_dict.get('username', '')} {password}"
            self._run_module(line)
        else:
            output = self.query_one("#output", RichLog)
            output.write("Password prompt cancelled.")

    @work(exclusive=True, thread=True)
    def _run_module(self, line: str) -> None:
        output = self.query_one("#output", RichLog)

        cmd, arg_string, _ = self.dispatcher.parseline(line)
        if cmd is None or cmd == '':
            return

        if cmd not in self.modules:
            self.call_from_thread(output.write, f"Module {cmd} not found")
            return

        try:
            args_dict = self.dispatcher.parse_module_args(cmd, arg_string)
            if not self.dispatcher.check_args_exist(cmd, args_dict):
                self.call_from_thread(
                    output.write,
                    f"*** Missing required arguments for {cmd}. Use `help {cmd}` to see available arguments."
                )
                return

            with OutputCapture(output, self):
                module = self.modules[cmd](
                    args_dict,
                    self.domain_dumper,
                    self.client,
                    logging.getLogger('ldap-shell')
                )
                result = module()

            if result and isinstance(result, str) and result.strip().endswith('# '):
                new_prompt = result.strip()
                self.prompt_text = new_prompt
                self.call_from_thread(
                    self.query_one("#prompt-label", Static).update,
                    new_prompt
                )
        except Exception as e:
            import traceback
            self.call_from_thread(
                output.write,
                f"Error: {e}\n{traceback.format_exc()}"
            )
