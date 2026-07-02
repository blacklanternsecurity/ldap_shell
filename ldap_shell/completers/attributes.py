from .base import BaseArgumentCompleter, CompletionItem

class AttributesCompleter(BaseArgumentCompleter):
    """Completer for LDAP attributes"""
    
    COMMON_LDAP_ATTRIBUTES = [
		'objectSid', 'objectGUID', 'objectClass', 'cn', 'sn', 'givenName', 'displayName',
		'name', 'sAMAccountName', 'sAMAccountType', 'userPrincipalName', 'userAccountControl',
		'accountExpires', 'adminCount', 'badPasswordTime', 'badPwdCount', 'codePage',
		'countryCode', 'description', 'distinguishedName', 'groupType', 'homeDirectory',
		'homeDrive', 'lastLogoff', 'lastLogon', 'lastLogonTimestamp', 'logonCount',
		'mail', 'memberOf', 'primaryGroupID', 'profilePath', 'pwdLastSet',
		'scriptPath', 'servicePrincipalName', 'trustDirection', 'trustType',
		'whenChanged', 'whenCreated', 'objectCategory', 'dSCorePropagationData',
		'instanceType', 'uSNChanged', 'uSNCreated'
	]
    
    def get_completions(self, full_text: str, current_word: str) -> list[CompletionItem]:
        # Split current input by comma
        if ',' in current_word:
            prefix = ','.join(current_word.split(',')[:-1]) + ','
            current_word = current_word.split(',')[-1].strip()
        else:
            prefix = ''

        completions = []
        for attr in self.COMMON_LDAP_ATTRIBUTES:
            if current_word.lower() in attr.lower():
                new_text = prefix + attr
                completions.append(CompletionItem(
                    text=new_text,
                    display=attr,
                    display_meta="LDAP attribute",
                    start_position=-(len(current_word) + len(prefix))
                ))

        return completions
