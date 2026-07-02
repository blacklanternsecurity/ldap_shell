import os
from typing import List


class CommandHistory:
    def __init__(self, filepath: str):
        self._filepath = filepath
        self._entries: List[str] = []
        self._load()

    def _load(self):
        if not os.path.exists(self._filepath):
            return
        with open(self._filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.rstrip('\n')
                if not line or line.startswith('#'):
                    continue
                # prompt_toolkit FileHistory uses '+' prefix for content lines
                if line.startswith('+'):
                    line = line[1:]
                self._entries.append(line)

    def append(self, entry: str):
        entry = entry.strip()
        if not entry:
            return
        self._entries.append(entry)
        with open(self._filepath, 'a', encoding='utf-8') as f:
            f.write(entry + '\n')

    def get_strings(self) -> List[str]:
        return list(self._entries)

    def __len__(self):
        return len(self._entries)
