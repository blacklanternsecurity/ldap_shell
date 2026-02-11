"""
ADWS Connection Adapter for ldap_shell

This module provides an adapter that makes ADWS (Active Directory Web Services)
compatible with ldap_shell's ldap3.Connection interface, allowing ldap_shell
modules to work transparently with either LDAP or ADWS.
"""

import logging
from base64 import b64decode
from typing import Any, Dict, List, Optional, Generator
from uuid import UUID
from xml.etree import ElementTree

from ldap_shell.lib.soapy import ADWSConnect, NTLMAuth, KerberosAuth, NAMESPACES
from impacket.ldap.ldaptypes import LDAP_SID

log = logging.getLogger('ldap-shell')


class ADWSEntry:
    """
    Mimics ldap3.Entry to provide compatibility with ldap_shell modules.
    """

    def __init__(self, dn: str, attributes: Dict[str, Any], raw_attributes: Dict[str, Any]):
        self.entry_dn = dn
        self._attributes = attributes
        self._raw_attributes = raw_attributes

    @property
    def entry_attributes_as_dict(self) -> Dict[str, List[Any]]:
        """Return attributes in the format expected by ldap_shell modules."""
        result = {}
        for key, value in self._attributes.items():
            # Ensure all values are lists for consistency
            if isinstance(value, list):
                result[key] = value
            else:
                result[key] = [value]
        return result

    def __getitem__(self, key: str):
        """Allow dictionary-style attribute access."""
        return self._attributes.get(key)

    def __contains__(self, key: str) -> bool:
        """Check if attribute exists."""
        return key in self._attributes


class ADWSServer:
    """
    Mimics ldap3.Server to provide server information.
    """

    def __init__(self, host: str, port: int = 9389):
        self.host = host
        self.port = port
        self.info = None  # Could populate with server info if needed


class ADWSConnection:
    """
    ADWS Connection adapter that provides an ldap3.Connection-compatible interface.

    This class wraps the low-level ADWSConnect class and provides methods
    that mimic ldap3.Connection behavior, allowing it to be used as a drop-in
    replacement for ldap3 in ldap_shell.
    """

    # Binary attributes that need base64 decoding
    BINARY_ATTRIBUTES = {
        "cACertificate",
        "userCertificate",
        "nTSecurityDescriptor",
        "msDS-AllowedToActOnBehalfOfOtherIdentity",
        "dnsRecord",
        "pKIExpirationPeriod",
        "pKIOverlapPeriod",
        "logonHours",
        "schemaIDGUID",
        "attributeSecurityGUID",
        "msDS-GroupMSAMembership",
    }

    # Attributes that should always be stored as lists
    ARRAY_ATTRIBUTES = {
        "member",
        "memberOf",
        "msDS-AllowedToDelegateTo",
        "pKIExtendedKeyUsage",
        "servicePrincipalName",
        "certificateTemplates",
        "cACertificate",
        "sIDHistory",
        "objectClass",
    }

    # Attributes that should be converted to integers
    INTEGER_ATTRIBUTES = {
        "userAccountControl",
        "systemFlags",
        "sAMAccountType",
        "groupType",
        "primaryGroupID",
        "instanceType",
        "msDS-SupportedEncryptionTypes",
        "trustDirection",
        "trustType",
        "trustAttributes",
        "searchFlags",
        "adminCount",
        "logonCount",
        "badPwdCount",
    }

    def __init__(self, hostname: str, domain: str, username: str,
                 password: Optional[str] = None, nt_hash: Optional[str] = None,
                 tgt: Optional[dict] = None, tgs: Optional[dict] = None,
                 target_realm: Optional[str] = None):
        """
        Initialize ADWS connection adapter.

        Args:
            hostname: DC hostname or IP to connect to
            domain: Domain name (e.g., 'contoso.local')
            username: Username for authentication
            password: Password for authentication (if using password auth)
            nt_hash: NT hash for authentication (if using hash auth)
            tgt: TGT dictionary for Kerberos authentication
            tgs: TGS dictionary for Kerberos authentication
            target_realm: Target realm for cross-realm Kerberos authentication
        """
        self.hostname = hostname
        self.domain = domain
        self.username = username
        self.base_dn = ','.join([f'DC={part}' for part in domain.split('.')])

        # Create server object
        self.server = ADWSServer(hostname)

        # Connection state
        self.bound = False
        self.closed = False
        self.entries = []
        self.result = {'result': -1, 'description': 'Not connected', 'message': ''}

        # ADWS clients (will be created on connect)
        self._pull_client: Optional[ADWSConnect] = None
        self._put_client: Optional[ADWSConnect] = None

        # Create auth object
        if tgt is not None:
            # Kerberos authentication
            self._auth = KerberosAuth(tgt=tgt, tgs=tgs, target_realm=target_realm,
                                     password=password, nt_hash=nt_hash)
        elif nt_hash:
            # NTLM with hash
            self._auth = NTLMAuth(hashes=nt_hash)
        elif password:
            # NTLM with password
            self._auth = NTLMAuth(password=password)
        else:
            raise ValueError("Either password, nt_hash, or tgt must be provided")

        # User string for compatibility
        self.user = f"{domain}\\{username}"

        # Schema cache
        self._schema_classes: Optional[set] = None

    def bind(self) -> bool:
        """
        Establish connection to ADWS server.

        Returns:
            True if connection successful, False otherwise
        """
        try:
            log.debug('Connecting to ADWS server: %s', self.hostname)

            # Create pull client (for enumeration/search operations)
            self._pull_client = ADWSConnect.pull_client(
                ip=self.hostname,
                domain=self.domain,
                username=self.username,
                auth=self._auth,
            )

            log.debug('Successfully connected to ADWS (pull client)')

            # Create put client (for modification operations)
            try:
                self._put_client = ADWSConnect.put_client(
                    ip=self.hostname,
                    domain=self.domain,
                    username=self.username,
                    auth=self._auth,
                )
                log.debug('Successfully connected to ADWS (put client)')
            except Exception as e:
                log.warning('Failed to create ADWS put client: %s', e)
                log.warning('Modification operations will not be available')

            self.bound = True
            self.closed = False
            self.result = {'result': 0, 'description': 'success', 'message': ''}

            return True

        except Exception as e:
            log.error('ADWS connection failed: %s', str(e))
            self.result = {
                'result': 1,
                'description': 'ADWS connection failed',
                'message': str(e)
            }
            return False

    @property
    def configuration_naming_context(self) -> str:
        """Return configuration partition base DN."""
        return f"CN=Configuration,{self.base_dn}"

    @property
    def schema_naming_context(self) -> str:
        """Return schema partition base DN."""
        return f"CN=Schema,CN=Configuration,{self.base_dn}"

    def search(self, search_base: str, search_filter: str,
               attributes: Optional[List[str]] = None,
               search_scope: str = 'SUBTREE') -> bool:
        """
        Search via ADWS, populating self.entries with results.

        Args:
            search_base: Base DN for search
            search_filter: LDAP filter string
            attributes: List of attributes to retrieve
            search_scope: Search scope (ignored for ADWS, always subtree)

        Returns:
            True if search succeeded, False otherwise
        """
        if not self.bound or self._pull_client is None:
            log.error('Not connected to ADWS server')
            return False

        # Clear previous results
        self.entries = []

        # ADWS requires explicit attribute lists
        if attributes is None or len(attributes) == 0 or attributes == ['*']:
            attr_list = ['*', 'distinguishedName', 'objectSid', 'objectClass']
        else:
            attr_list = list(attributes)
            # Ensure DN is always included
            if 'distinguishedName' not in attr_list:
                attr_list.append('distinguishedName')

        try:
            results_xml = self._pull_client.pull(
                query=search_filter,
                attributes=attr_list,
                search_base=search_base if search_base else self.base_dn,
            )

            for entry in self._parse_xml_entries(results_xml):
                self.entries.append(entry)

            self.result = {'result': 0, 'description': 'success', 'message': ''}
            return True

        except Exception as e:
            log.error('ADWS search %r failed: %s', search_filter, e)
            self.result = {
                'result': 1,
                'description': 'Search failed',
                'message': str(e)
            }
            return False

    def modify(self, dn: str, changes: Dict[str, Any]) -> bool:
        """
        Modify an object via ADWS.

        Args:
            dn: Distinguished name of object to modify
            changes: Dictionary of changes to apply

        Returns:
            True if modification succeeded, False otherwise
        """
        if not self.bound or self._put_client is None:
            log.error('ADWS put client not available for modifications')
            return False

        try:
            # Convert ldap3-style changes to ADWS put operations
            # This is a simplified implementation - may need expansion
            for attr, change_list in changes.items():
                for change in change_list:
                    operation = change[0]  # MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE
                    values = change[1]

                    # Map ldap3 operations to ADWS operations
                    if operation == 'MODIFY_ADD':
                        adws_op = 'Add'
                    elif operation == 'MODIFY_DELETE':
                        adws_op = 'Delete'
                    elif operation == 'MODIFY_REPLACE':
                        adws_op = 'Replace'
                    else:
                        log.warning('Unknown modify operation: %s', operation)
                        continue

                    # ADWS put only handles one value at a time
                    for value in values:
                        self._put_client.put(
                            object_ref=dn,
                            operation=adws_op,
                            attribute=attr,
                            data_type='string',  # Could be smarter about type detection
                            value=str(value)
                        )

            self.result = {'result': 0, 'description': 'success', 'message': ''}
            return True

        except Exception as e:
            log.error('ADWS modify failed: %s', str(e))
            self.result = {
                'result': 1,
                'description': 'Modify failed',
                'message': str(e)
            }
            return False

    def _parse_xml_entries(self, xml_root: ElementTree.Element) -> Generator[ADWSEntry, None, None]:
        """
        Convert ADWS XML response to ADWSEntry objects.

        Args:
            xml_root: Root XML element from ADWS response

        Yields:
            ADWSEntry objects compatible with ldap3.Entry
        """
        # Find all items in the response
        for items in xml_root.findall(".//wsen:Items", namespaces=NAMESPACES):
            for item in items:
                entry = self._parse_xml_item(item)
                if entry is not None:
                    yield entry

    def _parse_xml_item(self, item: ElementTree.Element) -> Optional[ADWSEntry]:
        """
        Parse a single ADWS XML item into an ADWSEntry.

        Args:
            item: XML element representing an AD object

        Returns:
            ADWSEntry object or None if parsing fails
        """
        attributes: Dict[str, Any] = {}
        raw_attributes: Dict[str, Any] = {}
        dn = None

        for attr in item:
            attr_name = attr.tag.split("}")[-1] if "}" in attr.tag else attr.tag

            # Get all values for this attribute
            values = []
            raw_values = []

            # Try ad:value namespace
            value_elems = attr.findall(".//{http://schemas.microsoft.com/2008/1/ActiveDirectory}value")

            for value_elem in value_elems:
                text = value_elem.text
                if text is None:
                    text = "".join(value_elem.itertext())

                if text is not None and len(text) > 0:
                    values.append(text)
                    raw_values.append(text)

            if not values:
                continue

            # Handle special attribute types
            if attr_name == "distinguishedName":
                dn = values[0]

            # Convert SID attributes
            if attr_name in ["objectSid", "securityIdentifier"]:
                try:
                    decoded_values = []
                    for v in values:
                        sid = LDAP_SID(data=b64decode(v))
                        decoded_values.append(sid.formatCanonical())
                    values = decoded_values
                except Exception:
                    pass

            # Handle sIDHistory (array of SIDs)
            elif attr_name == "sIDHistory":
                try:
                    decoded_values = []
                    for v in values:
                        sid = LDAP_SID(data=b64decode(v))
                        decoded_values.append(sid.formatCanonical())
                    values = decoded_values
                    raw_values = [b64decode(v) for v in raw_values]
                except Exception:
                    pass

            # Convert GUID attributes
            elif attr_name == "objectGUID":
                try:
                    decoded_values = []
                    for v in values:
                        guid = UUID(bytes_le=b64decode(v))
                        decoded_values.append("{" + str(guid) + "}")
                    values = decoded_values
                except Exception:
                    pass

            # Handle schemaIDGUID (binary GUID)
            elif attr_name == "schemaIDGUID":
                try:
                    raw_values = [b64decode(v) for v in values]
                    values = raw_values
                except Exception:
                    pass

            # Handle binary attributes
            elif attr_name in self.BINARY_ATTRIBUTES:
                try:
                    raw_values = [b64decode(v) for v in values]
                    values = raw_values
                except Exception:
                    pass

            # Convert integer attributes from string to int
            elif attr_name in self.INTEGER_ATTRIBUTES:
                try:
                    values = [int(v) for v in values]
                    raw_values = values
                except (ValueError, TypeError):
                    pass

            else:
                # For string attributes, raw_attributes should contain bytes
                raw_values = [v.encode("utf-8") if isinstance(v, str) else v for v in values]

            # Store single value or list based on count and attribute type
            if len(values) == 1 and attr_name not in self.ARRAY_ATTRIBUTES:
                attributes[attr_name] = values[0]
            else:
                attributes[attr_name] = values

            # Same logic for raw_attributes
            if len(raw_values) == 1 and attr_name not in self.ARRAY_ATTRIBUTES:
                raw_attributes[attr_name] = raw_values[0]
            else:
                raw_attributes[attr_name] = raw_values

        if not attributes:
            return None

        # Return ADWSEntry object
        return ADWSEntry(dn=dn, attributes=attributes, raw_attributes=raw_attributes)

    def unbind(self) -> bool:
        """
        Close the ADWS connection.

        Returns:
            True
        """
        self.bound = False
        self.closed = True
        log.debug('ADWS connection closed')
        return True

    def extend(self):
        """
        Placeholder for ldap3 extend operations.

        Returns:
            Self for basic compatibility
        """
        return self

    @property
    def standard(self):
        """Placeholder for ldap3 standard extended operations."""
        return self

    def who_am_i(self) -> str:
        """
        Return the authenticated user.

        Returns:
            User string in format domain\\username
        """
        return self.user
