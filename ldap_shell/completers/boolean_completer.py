from .base import BaseArgumentCompleter, CompletionItem

class BooleanCompleter(BaseArgumentCompleter):
    """Completer for boolean actions"""
    
    def get_completions(self, full_text: str, current_word: str) -> list[CompletionItem]:
        completions = []
        
        options = ['true', 'false']
        
        for option in options:
            if option.startswith(current_word.lower()):
                completions.append(CompletionItem(
                    text=option,
                    start_position=-len(current_word),
                    display=option,
                    display_meta="Action"
                ))
                
        return completions