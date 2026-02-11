"""
[MS-NNS]: .NET NegotiateStream Protocol

The .NET NegotiateStream Protocol provides mutually authenticated
and confidential communication over a TCP connection.

Modified for ldap_shell - NTLM and Kerberos authentication support.
"""

import datetime
import logging
import socket

import impacket.ntlm
import impacket.spnego
import impacket.structure
from Cryptodome.Cipher import ARC4
from impacket.hresult_errors import ERROR_MESSAGES
from impacket.krb5 import constants
from impacket.krb5.asn1 import AP_REQ, AP_REP, Authenticator, EncAPRepPart, TGS_REP, seq_set
from impacket.krb5.crypto import Key, _enctype_table
from impacket.krb5.types import Principal, KerberosTime, Ticket
from impacket.krb5.kerberosv5 import getKerberosTGS
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from .encoder.records.utils import Net7BitInteger


def hexdump(data, length=16):
    def to_ascii(byte):
        if 32 <= byte <= 126:
            return chr(byte)
        else:
            return "."

    def format_line(offset, line_bytes):
        hex_part = " ".join(f"{byte:02X}" for byte in line_bytes)
        ascii_part = "".join(to_ascii(byte) for byte in line_bytes)
        return f"{offset:08X}  {hex_part:<{length*3}}  {ascii_part}"

    lines = []
    for i in range(0, len(data), length):
        line_bytes = data[i : i + length]
        lines.append(format_line(i, line_bytes))

    return "\n".join(lines)


class NNS_pkt(impacket.structure.Structure):
    structure: tuple[tuple[str, str], ...]

    def send(self, sock: socket.socket):
        sock.sendall(self.getData())


class NNS_handshake(NNS_pkt):
    structure = (
        ("message_id", ">B"),
        ("major_version", ">B"),
        ("minor_version", ">B"),
        ("payload_len", ">H-payload"),
        ("payload", ":"),
    )

    def __init__(
        self, message_id: int, major_version: int, minor_version: int, payload: bytes
    ):
        impacket.structure.Structure.__init__(self)
        self["message_id"] = message_id
        self["major_version"] = major_version
        self["minor_version"] = minor_version
        self["payload"] = payload


class NNS_data(NNS_pkt):
    structure = (
        ("payload_size", "<L-payload"),
        ("payload", ":"),
    )


class NNS_Signed_payload(impacket.structure.Structure):
    structure = (
        ("signature", ":"),
        ("cipherText", ":"),
    )


class MessageID:
    IN_PROGRESS: int = 0x16
    ERROR: int = 0x15
    DONE: int = 0x14


class NNS:
    """[MS-NNS]: .NET NegotiateStream Protocol

    The .NET NegotiateStream Protocol provides mutually authenticated
    and confidential communication over a TCP connection.
    """

    def __init__(
        self,
        socket: socket.socket,
        fqdn: str,
        domain: str,
        username: str,
        password: str | None = None,
        nt: str = "",
        lm: str = "",
        tgt: dict | None = None,
        tgs: dict | None = None,
        target_realm: str | None = None,
    ):
        self._sock = socket

        self._nt = self._fix_hashes(nt)
        self._lm = self._fix_hashes(lm)

        self._username = username
        self._password = password

        self._domain = domain
        self._fqdn = fqdn

        self._session_key: bytes = b""
        self._flags: int = -1
        self._sequence: int = 0

        # Kerberos support
        self._tgt = tgt
        self._tgs = tgs
        self._target_realm = target_realm
        # Set the kerberos target if TGT is provided
        self._kerberos_target = fqdn if tgt is not None else None

    def _fix_hashes(self, hash: str | bytes) -> bytes | str:
        """fixes up hash if present into bytes and
        ensures length is 32.

        If no hash is present, returns empty bytes
        """
        if not hash:
            return ""

        if len(hash) % 2:
            hash = hash.zfill(32)

        return bytes.fromhex(hash) if isinstance(hash, str) else hash

    def seal(self, data: bytes) -> tuple[bytes, bytes]:
        """seals data with the current context"""
        server = bool(
            self._flags & impacket.ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        )

        output, sig = impacket.ntlm.SEAL(
            self._flags,
            self._server_signing_key if server else self._client_signing_key,
            self._server_sealing_key if server else self._client_sealing_key,
            data,
            data,
            self._sequence,
            self._server_sealing_handle if server else self._client_sealing_handle,
        )

        return output, sig.getData()

    def recv(self, _: int = 0) -> bytes:
        """Receive an NNS packet and return the entire decrypted contents."""
        first_pkt = self._recv()

        # if it isn't an envelope, throw it back
        if first_pkt[0] != 0x06:
            return first_pkt

        nmfsize, nmflenlen = Net7BitInteger.decode7bit(first_pkt[1:])

        # it's all just one packet
        if nmfsize < 0xFC30:
            return first_pkt

        # otherwise, we have a multi part message
        pkt = first_pkt
        nmfsize -= len(first_pkt[nmflenlen:])

        while nmfsize > 0:
            thisFragment = self._recv()
            pkt += thisFragment
            nmfsize -= len(thisFragment)

        return pkt

    def _recv(self, _: int = 0) -> bytes:
        """Receive an NNS packet and return the entire decrypted contents."""
        nns_data = NNS_data()
        size = int.from_bytes(self._sock.recv(4), "little")

        payload = b""
        while len(payload) != size:
            payload += self._sock.recv(size - len(payload))
        nns_data["payload"] = payload

        # NTLM decryption
        nns_signed_payload = NNS_Signed_payload()
        nns_signed_payload["signature"] = nns_data["payload"][0:16]
        nns_signed_payload["cipherText"] = nns_data["payload"][16:]

        clearText, sig = self.seal(nns_signed_payload["cipherText"])
        return clearText

    def sendall(self, data: bytes):
        """send to server in sealed NNS data packet via tcp socket."""
        # NTLM encryption
        cipherText, sig = impacket.ntlm.SEAL(
            self._flags,
            self._client_signing_key,
            self._client_sealing_key,
            data,
            data,
            self._sequence,
            self._client_sealing_handle,
        )

        # build the NNS data packet
        pkt = NNS_data()

        # payload is signature prepended on the ciphertext
        payload = NNS_Signed_payload()
        payload["signature"] = sig
        payload["cipherText"] = cipherText
        pkt["payload"] = payload.getData()

        self._sock.sendall(pkt.getData())

        # increment the sequence number after sending
        self._sequence += 1

    def auth_ntlm(self) -> None:
        """Authenticate to the dest with NTLMV2 authentication"""

        # Generate a NTLMSSP
        NtlmSSP_nego = impacket.ntlm.getNTLMSSPType1(
            workstation="",
            domain="",
            signingRequired=True,
            use_ntlmv2=True,
        )

        # Generate the NegTokenInit
        NegTokenInit = impacket.spnego.SPNEGO_NegTokenInit()
        NegTokenInit["MechTypes"] = [
            impacket.spnego.TypesMech[
                "NTLMSSP - Microsoft NTLM Security Support Provider"
            ],
            impacket.spnego.TypesMech["MS KRB5 - Microsoft Kerberos 5"],
            impacket.spnego.TypesMech["KRB5 - Kerberos 5"],
            impacket.spnego.TypesMech[
                "NEGOEX - SPNEGO Extended Negotiation Security Mechanism"
            ],
        ]
        NegTokenInit["MechToken"] = NtlmSSP_nego.getData()

        # Begin authentication (NTLMSSP_NEGOTIATE)
        NNS_handshake(
            message_id=MessageID.IN_PROGRESS,
            major_version=1,
            minor_version=0,
            payload=NegTokenInit.getData(),
        ).send(self._sock)

        # Receive the NNS NTLMSSP_Challenge
        NNS_msg_chall = NNS_handshake(
            message_id=int.from_bytes(self._sock.recv(1), "big"),
            major_version=int.from_bytes(self._sock.recv(1), "big"),
            minor_version=int.from_bytes(self._sock.recv(1), "big"),
            payload=self._sock.recv(int.from_bytes(self._sock.recv(2), "big")),
        )

        # Extract the NegTokenResp
        s_NegTokenTarg = impacket.spnego.SPNEGO_NegTokenResp(NNS_msg_chall["payload"])

        # Create an NtlmAuthChallenge from the NTLMSSP (ResponseToken)
        NTLMSSP_chall = impacket.ntlm.NTLMAuthChallenge(s_NegTokenTarg["ResponseToken"])

        # Create the NTLMSSP challenge response
        NTLMSSP_chall_resp, self._session_key = impacket.ntlm.getNTLMSSPType3(
            type1=NtlmSSP_nego,
            type2=NTLMSSP_chall.getData(),
            user=self._username,
            password=self._password,
            domain=self._domain,
            lmhash=self._lm,
            nthash=self._nt,
        )

        # set up info for crypto
        self._flags = NTLMSSP_chall_resp["flags"]
        self._sequence = 0

        if self._flags & impacket.ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
            logging.debug("Using extended NTLM security")
            self._client_signing_key = impacket.ntlm.SIGNKEY(
                self._flags, self._session_key
            )
            self._server_signing_key = impacket.ntlm.SIGNKEY(
                self._flags, self._session_key, "Server"
            )
            self._client_sealing_key = impacket.ntlm.SEALKEY(
                self._flags, self._session_key
            )
            self._server_sealing_key = impacket.ntlm.SEALKEY(
                self._flags, self._session_key, "Server"
            )

            # prepare keys to handle states
            cipher1 = ARC4.new(self._client_sealing_key)
            self._client_sealing_handle = cipher1.encrypt
            cipher2 = ARC4.new(self._server_sealing_key)
            self._server_sealing_handle = cipher2.encrypt

        else:
            logging.debug("Using basic NTLM auth")
            # same key for both ways
            self._client_signing_key = self._session_key
            self._server_signing_key = self._session_key
            self._client_sealing_key = self._session_key
            self._server_sealing_key = self._session_key
            cipher = ARC4.new(self._client_sealing_key)
            self._client_sealing_handle = cipher.encrypt
            self._server_sealing_handle = cipher.encrypt

        # Fit the challenge response into the ResponseToken of our NegTokenTarg
        c_NegTokenTarg = impacket.spnego.SPNEGO_NegTokenResp()
        c_NegTokenTarg["ResponseToken"] = NTLMSSP_chall_resp.getData()

        # Send the NTLMSSP_AUTH (challenge response)
        NNS_handshake(
            message_id=MessageID.IN_PROGRESS,
            major_version=1,
            minor_version=0,
            payload=c_NegTokenTarg.getData(),
        ).send(self._sock)

        # Check for success
        NNS_msg_done = NNS_handshake(
            message_id=int.from_bytes(self._sock.recv(1), "big"),
            major_version=int.from_bytes(self._sock.recv(1), "big"),
            minor_version=int.from_bytes(self._sock.recv(1), "big"),
            payload=self._sock.recv(int.from_bytes(self._sock.recv(2), "big")),
        )

        # check for errors
        if NNS_msg_done["message_id"] == 0x15:
            err_type, err_msg = ERROR_MESSAGES[
                int.from_bytes(NNS_msg_done["payload"], "big")
            ]
            raise SystemExit(f"[-] NTLM Auth Failed with error {err_type} {err_msg}")

    def auth_kerberos(self) -> None:
        """Authenticate to the dest with Kerberos authentication using pyspnego"""
        try:
            import spnego
            from spnego import NegotiateOptions
        except ImportError:
            logging.error("pyspnego library not installed. Install with: pip install pyspnego[kerberos]")
            raise SystemExit("[-] pyspnego library required for Kerberos authentication")

        import os
        import tempfile
        from impacket.krb5.ccache import CCache

        logging.debug("Attempting Kerberos authentication to ADWS using pyspnego")

        temp_ccache = None
        temp_krb5conf = None
        original_krb5ccname = os.environ.get('KRB5CCNAME')
        original_krb5_config = os.environ.get('KRB5_CONFIG')

        try:
            # If we have TGT/TGS from impacket, write them to a temporary ccache
            # so pyspnego can read them via GSSAPI
            if self._tgt is not None:
                logging.debug("Writing TGT/TGS to temporary ccache for pyspnego")

                # Create a temporary krb5.conf to configure GSSAPI properly
                temp_fd, temp_krb5conf = tempfile.mkstemp(prefix='krb5_', suffix='.conf')
                krb5conf_content = f"""[libdefaults]
    default_realm = {self._domain.upper()}
    dns_lookup_realm = false
    dns_lookup_kdc = false
    rdns = false
    dns_canonicalize_hostname = false

[realms]
    {self._domain.upper()} = {{
        kdc = {self._fqdn}
        admin_server = {self._fqdn}
    }}

[domain_realm]
    .{self._domain.lower()} = {self._domain.upper()}
    {self._domain.lower()} = {self._domain.upper()}
"""
                os.write(temp_fd, krb5conf_content.encode('utf-8'))
                os.close(temp_fd)
                os.environ['KRB5_CONFIG'] = temp_krb5conf
                logging.debug(f"Created temporary krb5.conf: {temp_krb5conf}")

                # Create a temporary ccache file
                temp_fd, temp_ccache = tempfile.mkstemp(prefix='krb5cc_ldapshell_', suffix='.ccache')
                os.close(temp_fd)

                # Create CCache object
                ccache = CCache()
                ccache.fromTGT(self._tgt['KDC_REP'], self._tgt['oldSessionKey'], self._tgt['sessionKey'])

                # If we have TGS, add it too
                if self._tgs is not None:
                    # Extract the service principal from TGS
                    tgs_rep = self._tgs['KDC_REP']
                    service_principal = f"HOST/{self._fqdn}@{self._domain.upper()}"
                    ccache.fromTGS(self._tgs['KDC_REP'], self._tgs['oldSessionKey'], self._tgs['sessionKey'])

                # Save the ccache to the temp file
                ccache.saveFile(temp_ccache)

                # Set KRB5CCNAME to point to our temp ccache
                os.environ['KRB5CCNAME'] = temp_ccache
                logging.debug(f"Set KRB5CCNAME to temporary ccache: {temp_ccache}")

                # Debug: List credentials in the ccache
                import subprocess
                try:
                    klist_output = subprocess.run(
                        ['klist', '-c', temp_ccache],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    logging.debug(f"klist output:\n{klist_output.stdout}")
                    if klist_output.stderr:
                        logging.debug(f"klist stderr:\n{klist_output.stderr}")
                except Exception as e:
                    logging.debug(f"Failed to run klist: {e}")

            # Create SPNEGO client context for Kerberos authentication
            # The hostname should be the FQDN of the DC for proper SPN resolution
            logging.debug(f"Creating SPNEGO client for {self._username}@{self._domain.upper()} -> {self._fqdn}")

            # Build the client context
            # pyspnego will handle the GSSAPI/SSPI calls to get Kerberos tickets
            # If we created a temp ccache above, use it without password (GSSAPI will read from ccache)
            # If we didn't create a temp ccache, use password (pyspnego will get tickets directly)
            use_password = self._password if temp_ccache is None else None

            client = spnego.client(
                username=f"{self._username}@{self._domain.upper()}",
                password=use_password,
                hostname=self._fqdn,
                service="HOST",  # ADWS uses the HOST service principal
                protocol="kerberos",  # Force Kerberos (don't fall back to NTLM)
                options=NegotiateOptions.use_gssapi,  # Use GSSAPI on Linux, SSPI on Windows
            )

            logging.debug("SPNEGO client created, generating initial token")

            # Generate the initial authentication token
            out_token = client.step()

            if not out_token:
                raise ValueError("pyspnego failed to generate initial Kerberos token")

            logging.debug(f"Generated Kerberos token ({len(out_token)} bytes)")

            # Send the initial token via NNS handshake
            NNS_handshake(
                message_id=MessageID.IN_PROGRESS,
                major_version=1,
                minor_version=0,
                payload=out_token,
            ).send(self._sock)

            logging.debug("Sent initial Kerberos token to server")

            # Receive server response
            NNS_msg_resp = NNS_handshake(
                message_id=int.from_bytes(self._sock.recv(1), "big"),
                major_version=int.from_bytes(self._sock.recv(1), "big"),
                minor_version=int.from_bytes(self._sock.recv(1), "big"),
                payload=self._sock.recv(int.from_bytes(self._sock.recv(2), "big")),
            )

            logging.debug(f"Received response with message_id: 0x{NNS_msg_resp['message_id']:02x}")
            logging.debug(f"Response payload length: {len(NNS_msg_resp['payload'])} bytes")

            # Check for errors
            if NNS_msg_resp["message_id"] == MessageID.ERROR:
                err_code = int.from_bytes(NNS_msg_resp["payload"], "big")
                logging.error(f"Server returned error code: {err_code} (0x{err_code:04x})")
                if err_code in ERROR_MESSAGES:
                    err_type, err_msg = ERROR_MESSAGES[err_code]
                    raise SystemExit(f"[-] Kerberos Auth Failed with error {err_type} {err_msg}")
                else:
                    raise SystemExit(f"[-] Kerberos Auth Failed with error code {err_code} (0x{err_code:08x})")

            # Continue authentication handshake if server sent more data
            while not client.complete and NNS_msg_resp["message_id"] == MessageID.IN_PROGRESS:
                in_token = NNS_msg_resp["payload"]
                logging.debug(f"Processing server token ({len(in_token)} bytes)")

                # Process server's response and generate next token
                out_token = client.step(in_token)

                if out_token:
                    logging.debug(f"Sending response token ({len(out_token)} bytes)")
                    NNS_handshake(
                        message_id=MessageID.IN_PROGRESS,
                        major_version=1,
                        minor_version=0,
                        payload=out_token,
                    ).send(self._sock)

                    # Receive next response
                    NNS_msg_resp = NNS_handshake(
                        message_id=int.from_bytes(self._sock.recv(1), "big"),
                        major_version=int.from_bytes(self._sock.recv(1), "big"),
                        minor_version=int.from_bytes(self._sock.recv(1), "big"),
                        payload=self._sock.recv(int.from_bytes(self._sock.recv(2), "big")),
                    )

                    logging.debug(f"Received response with message_id: 0x{NNS_msg_resp['message_id']:02x}")

                    # Check for errors
                    if NNS_msg_resp["message_id"] == MessageID.ERROR:
                        err_code = int.from_bytes(NNS_msg_resp["payload"], "big")
                        logging.error(f"Server returned error code: {err_code} (0x{err_code:04x})")
                        if err_code in ERROR_MESSAGES:
                            err_type, err_msg = ERROR_MESSAGES[err_code]
                            raise SystemExit(f"[-] Kerberos Auth Failed with error {err_type} {err_msg}")
                        else:
                            raise SystemExit(f"[-] Kerberos Auth Failed with error code {err_code} (0x{err_code:08x})")
                else:
                    # No more tokens to send, authentication should be complete
                    break

            if not client.complete:
                raise ValueError("Kerberos authentication did not complete successfully")

            logging.debug("Kerberos authentication handshake completed")

            # Extract the session key from pyspnego for NNS channel encryption
            try:
                session_key_bytes = client.session_key
                if not session_key_bytes:
                    logging.warning("No session key available from pyspnego, using fallback")
                    # Fallback: try to use a derived key (may not work)
                    session_key_bytes = b'\x00' * 16
                else:
                    logging.debug(f"Extracted session key ({len(session_key_bytes)} bytes)")

                self._session_key = session_key_bytes
                self._sequence = 0

                # Set up encryption keys for NNS channel
                # Use the Kerberos session key for signing and sealing
                self._flags = (
                    impacket.ntlm.NTLMSSP_NEGOTIATE_SIGN |
                    impacket.ntlm.NTLMSSP_NEGOTIATE_SEAL |
                    impacket.ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
                )

                # Derive encryption keys from session key
                self._client_signing_key = session_key_bytes[:16] if len(session_key_bytes) >= 16 else session_key_bytes
                self._server_signing_key = session_key_bytes[:16] if len(session_key_bytes) >= 16 else session_key_bytes
                self._client_sealing_key = session_key_bytes[:16] if len(session_key_bytes) >= 16 else session_key_bytes
                self._server_sealing_key = session_key_bytes[:16] if len(session_key_bytes) >= 16 else session_key_bytes

                # Initialize RC4 ciphers for NNS encryption
                cipher_client = ARC4.new(self._client_sealing_key)
                self._client_sealing_handle = cipher_client.encrypt
                cipher_server = ARC4.new(self._server_sealing_key)
                self._server_sealing_handle = cipher_server.encrypt

                logging.debug("NNS encryption initialized with Kerberos session key")

            except Exception as e:
                logging.error(f"Failed to extract session key from pyspnego: {e}")
                raise

            logging.debug("Kerberos authentication successful via pyspnego")

        except Exception as e:
            logging.error(f"Kerberos authentication failed: {e}")
            logging.debug("Exception details:", exc_info=True)
            raise
        finally:
            # Clean up temporary files and restore environment
            if temp_ccache is not None:
                try:
                    os.unlink(temp_ccache)
                    logging.debug(f"Deleted temporary ccache: {temp_ccache}")
                except Exception as e:
                    logging.warning(f"Failed to delete temporary ccache {temp_ccache}: {e}")

                # Restore original KRB5CCNAME
                if original_krb5ccname is not None:
                    os.environ['KRB5CCNAME'] = original_krb5ccname
                    logging.debug(f"Restored KRB5CCNAME to: {original_krb5ccname}")
                elif 'KRB5CCNAME' in os.environ:
                    del os.environ['KRB5CCNAME']
                    logging.debug("Removed temporary KRB5CCNAME from environment")

            if temp_krb5conf is not None:
                try:
                    os.unlink(temp_krb5conf)
                    logging.debug(f"Deleted temporary krb5.conf: {temp_krb5conf}")
                except Exception as e:
                    logging.warning(f"Failed to delete temporary krb5.conf {temp_krb5conf}: {e}")

                # Restore original KRB5_CONFIG
                if original_krb5_config is not None:
                    os.environ['KRB5_CONFIG'] = original_krb5_config
                    logging.debug(f"Restored KRB5_CONFIG to: {original_krb5_config}")
                elif 'KRB5_CONFIG' in os.environ:
                    del os.environ['KRB5_CONFIG']
                    logging.debug("Removed temporary KRB5_CONFIG from environment")
