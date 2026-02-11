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
from impacket.krb5.asn1 import AP_REQ, Authenticator, TGS_REP, seq_set
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
        """Authenticate to the dest with Kerberos authentication"""

        logging.debug("Attempting Kerberos authentication to ADWS")

        # Get or request TGS for the ADWS service
        if self._tgs is None:
            # Request a TGS for the ADWS service principal
            server_name = Principal(
                f'ADWS/{self._fqdn}',
                type=constants.PrincipalNameType.NT_SRV_INST.value
            )

            logging.debug(f'Requesting TGS for service: ADWS/{self._fqdn}')

            try:
                tgs, cipher, _, session_key = getKerberosTGS(
                    server_name,
                    self._domain,
                    self._fqdn,
                    self._tgt['KDC_REP'],
                    self._tgt['cipher'],
                    self._tgt['sessionKey']
                )
            except Exception as e:
                logging.error(f'Failed to get TGS for ADWS service: {e}')
                raise
        else:
            tgs = self._tgs['KDC_REP']
            cipher = self._tgs['cipher']
            session_key = self._tgs['sessionKey']

        # Build SPNEGO NegTokenInit with Kerberos AP_REQ
        blob = impacket.spnego.SPNEGO_NegTokenInit()
        blob['MechTypes'] = [
            impacket.spnego.TypesMech["MS KRB5 - Microsoft Kerberos 5"],
            impacket.spnego.TypesMech["KRB5 - Kerberos 5"],
        ]

        # Extract the ticket from the TGS
        tgs_decoded = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
        ticket = Ticket()
        ticket.from_asn1(tgs_decoded['ticket'])

        # Build the AP_REQ
        ap_req = AP_REQ()
        ap_req['pvno'] = 5
        ap_req['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

        opts = []
        ap_req['ap-options'] = constants.encodeFlags(opts)
        seq_set(ap_req, 'ticket', ticket.to_asn1)

        # Build authenticator
        authenticator = Authenticator()
        authenticator['authenticator-vno'] = 5
        authenticator['crealm'] = self._domain

        user_name = Principal(
            self._username,
            type=constants.PrincipalNameType.NT_PRINCIPAL.value
        )
        seq_set(authenticator, 'cname', user_name.components_to_asn1)

        now = datetime.datetime.utcnow()
        authenticator['cusec'] = now.microsecond
        authenticator['ctime'] = KerberosTime.to_asn1(now)

        encoded_authenticator = encoder.encode(authenticator)

        # Encrypt authenticator with session key (Key Usage 11)
        encrypted_encoded_authenticator = cipher.encrypt(
            session_key, 11, encoded_authenticator, None
        )

        ap_req['authenticator'] = noValue
        ap_req['authenticator']['etype'] = cipher.enctype
        ap_req['authenticator']['cipher'] = encrypted_encoded_authenticator

        blob['MechToken'] = encoder.encode(ap_req)

        # Send the Kerberos AP_REQ in NNS handshake
        logging.debug("Sending Kerberos AP_REQ")
        NNS_handshake(
            message_id=MessageID.IN_PROGRESS,
            major_version=1,
            minor_version=0,
            payload=blob.getData(),
        ).send(self._sock)

        # Receive server response
        NNS_msg_resp = NNS_handshake(
            message_id=int.from_bytes(self._sock.recv(1), "big"),
            major_version=int.from_bytes(self._sock.recv(1), "big"),
            minor_version=int.from_bytes(self._sock.recv(1), "big"),
            payload=self._sock.recv(int.from_bytes(self._sock.recv(2), "big")),
        )

        # Check for errors
        if NNS_msg_resp["message_id"] == MessageID.ERROR:
            err_type, err_msg = ERROR_MESSAGES[
                int.from_bytes(NNS_msg_resp["payload"], "big")
            ]
            raise SystemExit(f"[-] Kerberos Auth Failed with error {err_type} {err_msg}")

        # For Kerberos, we need to set up the session key for encryption
        # Use the Kerberos session key for NNS encryption
        self._session_key = session_key
        self._sequence = 0

        # Set up Kerberos-based encryption keys
        # Note: Kerberos uses different key derivation than NTLM
        # For now, we'll use the session key directly
        # This may need adjustment based on actual ADWS Kerberos implementation
        self._flags = (
            impacket.ntlm.NTLMSSP_NEGOTIATE_SIGN |
            impacket.ntlm.NTLMSSP_NEGOTIATE_SEAL |
            impacket.ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        )

        # Use Kerberos session key for signing and sealing
        self._client_signing_key = session_key[:16] if len(session_key) >= 16 else session_key
        self._server_signing_key = session_key[:16] if len(session_key) >= 16 else session_key
        self._client_sealing_key = session_key[:16] if len(session_key) >= 16 else session_key
        self._server_sealing_key = session_key[:16] if len(session_key) >= 16 else session_key

        # Initialize RC4 ciphers
        cipher_client = ARC4.new(self._client_sealing_key)
        self._client_sealing_handle = cipher_client.encrypt
        cipher_server = ARC4.new(self._server_sealing_key)
        self._server_sealing_handle = cipher_server.encrypt

        # Send final handshake message
        c_NegTokenTarg = impacket.spnego.SPNEGO_NegTokenResp()
        c_NegTokenTarg['NegResult'] = b'\x00'  # Accept completed

        NNS_handshake(
            message_id=MessageID.IN_PROGRESS,
            major_version=1,
            minor_version=0,
            payload=c_NegTokenTarg.getData(),
        ).send(self._sock)

        # Check for final success
        NNS_msg_done = NNS_handshake(
            message_id=int.from_bytes(self._sock.recv(1), "big"),
            major_version=int.from_bytes(self._sock.recv(1), "big"),
            minor_version=int.from_bytes(self._sock.recv(1), "big"),
            payload=self._sock.recv(int.from_bytes(self._sock.recv(2), "big")),
        )

        if NNS_msg_done["message_id"] == MessageID.ERROR:
            err_type, err_msg = ERROR_MESSAGES[
                int.from_bytes(NNS_msg_done["payload"], "big")
            ]
            raise SystemExit(f"[-] Kerberos Auth Failed at final stage with error {err_type} {err_msg}")

        logging.debug("Kerberos authentication successful")
