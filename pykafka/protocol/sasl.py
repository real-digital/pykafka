import struct

from pykafka.utils import struct_helpers
from .base import Request, Response


class SaslHandshakeRequest(Request):
    """A SASL handshake request.
    Specification::

    SaslHandshake Request (Version: 0) => mechanism
        mechanism => STRING
    """
    API_KEY = 17

    @classmethod
    def get_versions(cls):
        return {0: SaslHandshakeRequest, 1: SaslHandshakeRequestV1}

    def __init__(self, mechanism):
        self.mechanism = mechanism.encode()

    def __len__(self):
        return self.HEADER_LEN + 2 + len(self.mechanism)

    def get_bytes(self):
        """Create new sasl handshake request"""
        output = bytearray(len(self))
        self._write_header(output)
        offset = self.HEADER_LEN
        fmt = '!h%ds' % len(self.mechanism)
        struct.pack_into(fmt, output, offset, len(self.mechanism), self.mechanism)
        return output


class SaslHandshakeRequestV1(SaslHandshakeRequest):
    """A SASL handshake request.
    Specification::

    SaslHandshake Request (Version: 1) => mechanism
        mechanism => STRING
    """


class SaslHandshakeResponse(Response):
    """A SASL handshake response.
    Specification::

    SaslHandshake Response (Version: 0) => error_code [mechanisms]
        error_code => INT16
        mechanisms => STRING
    """
    API_KEY = 17

    @classmethod
    def get_versions(cls):
        return {0: SaslHandshakeRequest, 1: SaslHandshakeRequestV1}

    def __init__(self, buff):
        """Deserialize into a new Response

        :param buff: Serialized message
        :type buff: :class:`bytearray`
        """
        fmt = 'h [S]'
        response = struct_helpers.unpack_from(fmt, buff, 0)

        self.error_code = response[0]
        self.mechanisms = response[1]


class SaslHandshakeResponseV1(SaslHandshakeResponse):
    """A SASL handshake response.
    Specification::

    SaslHandshake Response (Version: 1) => error_code [mechanisms]
        error_code => INT16
        mechanisms => STRING
    """


class SaslAuthenticateRequest(Request):
    """A SASL authenticate request
    Specification::

    SaslAuthenticate Request (Version: 0) => auth_bytes
        auth_bytes => BYTES
    """
    API_KEY = 36

    @classmethod
    def get_versions(cls):
        return {0: SaslAuthenticateRequest, 1: SaslAuthenticateRquestV1}

    def __init__(self, auth_bytes):
        self.auth_bytes = auth_bytes

    def __len__(self):
        if self.auth_bytes is not None:
            return self.HEADER_LEN + 4 + len(self.auth_bytes)
        return self.HEADER_LEN + 4

    def get_bytes(self):
        """Create new sasl authenticate request"""
        output = bytearray(len(self))
        self._write_header(output)
        offset = self.HEADER_LEN
        if self.auth_bytes is not None:
            fmt = '!i%ds' % len(self.auth_bytes)
            struct.pack_into(fmt, output, offset, len(self.auth_bytes), self.auth_bytes)
        else:
            fmt = '!i'
            struct.pack_into(fmt, output, offset, -1)
        return output


class SaslAuthenticateRquestV1(SaslAuthenticateRequest):
    """A SASL authenticate request
    Specification::

    SaslAuthenticate Request (Version: 1) => auth_bytes
        auth_bytes => BYTES
    """


class SaslAuthenticateResponse(Response):
    """A SASL authenticate response
    Specification::

    SaslAuthenticate Response (Version: 0) => error_code error_message auth_bytes
        error_code => INT16
        error_message => NULLABLE_STRING
        auth_bytes => BYTES
    """
    API_KEY = 36

    @classmethod
    def get_versions(cls):
        return {0: SaslAuthenticateResponse, 1: SaslAuthenticateResponseV1}

    def __init__(self, buff):
        """Deserialize into a new Response

        :param buff: Serialized message
        :type buff: :class:`bytearray`
        """
        fmt = 'h S Y'
        response = struct_helpers.unpack_from(fmt, buff, 0)

        self.error_code = response[0]
        self.error_message = response[1].decode()
        self.auth_bytes = response[2]


class SaslAuthenticateResponseV1(SaslAuthenticateResponse):
    """A SASL authenticate response
    Specification::

    SaslAuthenticate Response (Version: 1) => error_code error_message auth_bytes session_lifetime_ms
        error_code => INT16
        error_message => NULLABLE_STRING
        auth_bytes => BYTES
        session_lifetime_ms => INT64
    """

    def __init__(self, buff):
        """Deserialize into a new Response

        :param buff: Serialized message
        :type buff: :class:`bytearray`
        """
        fmt = 'h S Y q'
        response = struct_helpers.unpack_from(fmt, buff, 0)

        self.error_code = response[0]
        self.error_message = response[1].decode()
        self.auth_bytes = response[2]
        self.session_lifetime_ms = response[3]
