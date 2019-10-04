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