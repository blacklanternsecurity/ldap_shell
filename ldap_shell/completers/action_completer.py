from .base import BaseArgumentCompleter, CompletionItem

class ActionCompleter(BaseArgumentCompleter):
    """Completer for add/del actions"""
    
    def get_completions(self, full_text: str, current_word: str) -> list[CompletionItem]:
        completions = []
        
        options = ['add', 'del', 'list']
        
        for option in options:
            if option.startswith(current_word.lower()):
                completions.append(CompletionItem(
                    text=option,
                    start_position=-len(current_word),
                    display=option,
                    display_meta="Action"
                ))
                
        return completions