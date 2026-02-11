import logging
from ldap3 import Connection, SUBTREE, MODIFY_ADD
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from typing import Optional
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType

class LdapShellModule(BaseLdapModule):
    """Module for adding new groups to Active Directory"""

    help_text = "Add new group to Active Directory"
    examples_text = """
    Add a new group to default location (CN=Users)
    `add_group "Test Group"`

    Add a new group to specific OU
    `add_group "Test Group" "OU=testOU,DC=roasting,DC=lab"`
    """
    module_type = "Misc"

    class ModuleArgs(BaseModel):
        group_name: str = Field(
            ...,  # This argument is required
            description="Name of the group to create",
            arg_type=[ArgumentType.STRING]
        )
        target_dn: Optional[str] = Field(
            None,
            description="Target OU where to create the group (optional)",
            arg_type=[ArgumentType.DN]
        )
    
    def __init__(self, args_dict: dict, 
                 domain_dumper: domainDumper, 
                 client: Connection,
                 log=None):
        self.args = self.ModuleArgs(**args_dict) 
        self.domain_dumper = domain_dumper
        self.client = client
        self.log = log or logging.getLogger('ldap-shell.shell')

    def __call__(self):
        # Check if group already exists
        self.client.search(
            self.domain_dumper.root,
            f'(&(objectClass=group)(sAMAccountName={self.args.group_name}))',
            SUBTREE,
            attributes=['distinguishedName']
        )
        
        if len(self.client.entries) > 0:
            self.log.error(f"Group {self.args.group_name} already exists")
            return

        # Form DN for new group
        if self.args.target_dn:
            group_dn = f"CN={self.args.group_name},{self.args.target_dn}"
        else:
            group_dn = f"CN={self.args.group_name},CN=Users,{self.domain_dumper.root}"

        # Attributes for group creation (simplified, matching ADWS patterns)
        # Note: cn and name are auto-generated from DN, don't send them
        group_attributes = {
            'sAMAccountName': self.args.group_name,
            'description': f"Group created via ldap_shell"
        }

        # Create group - use correct signature: add(dn, object_class_list, attributes_dict)
        if self.client.add(group_dn, ['group'], group_attributes):
            self.log.info(f"Group {self.args.group_name} created successfully at {group_dn}")
        else:
            self.log.error(f"Failed to create group {self.args.group_name}: {self.client.result}")