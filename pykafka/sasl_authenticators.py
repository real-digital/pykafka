import base64
import hashlib
import hmac
import logging
import struct
from uuid import uuid4

import six

from .exceptions import AuthenticationException, ERROR_CODES, UnsupportedSaslMechanism
from .protocol import (SaslHandshakeRequest, SaslHandshakeResponse, ApiVersionsRequest, ApiVersionsResponse,
    SaslAuthenticateRequest, SaslAuthenticateResponse)

log = logging.getLogger(__name__)


if six.PY2:
    def xor_bytes(left, right):
        return bytearray(ord(lb) ^ ord(rb) for lb, rb in zip(left, right))
else:
    def xor_bytes(left, right):
        return bytes(lb ^ rb for lb, rb in zip(left, right))


class FakeRequest:
    def __init__(self, payload):
        self.payload = payload

    def get_bytes(self):
        return struct.pack("!i", len(self.payload)) + self.payload


class BaseAuthenticator:
    """
    Base class for authentication mechanisms.
    Subclasses are supposed to implement:
     1. :meth:`BaseAuthenticator.get_rd_kafka_opts` which should return a dictionary
        whose items will be appended to the config given to librdkafka consumers and producers.
     2. :meth:`BaseAuthenticator.exchange_tokens` which is supposed to use :meth:`BaseAuthenticator.send_token`
        and :meth:`BaseAuthenticator.receive_token` to send and receive the byte strings necessary to authenticate
        with the broker.
    """
    MAX_AUTH_VERSION = 1
    MAX_HANDSHAKE_VERSION = 1

    def __init__(self, mechanism, security_protocol=None):
        """
        Base class for SASL authentication mechanisms.

        :param mechanism: The mechanism this authenticator is supposed to use.
        :type mechanism: str
        :param security_protocol: The security protocol determining the broker endpoint this
                                  authenticator is supposed to authenticate with.
                                  Only used for rdkafka based consumers and producers.
        """

        self.mechanism = mechanism
        self.handshake_version = None
        self.auth_version = None
        self.security_protocol = security_protocol
        self._broker_connection = None

    def get_rd_kafka_opts(self):
        raise NotImplementedError()

    def authenticate(self, broker_connection):
        self._broker_connection = broker_connection
        if self.handshake_version is None:
            self.fetch_api_versions()
        log.debug(
            "Authenticating to {}:{} using mechanism {}.".format(
                self._broker_connection.host, self._broker_connection.port, self.mechanism
            )
        )
        self.initialize_authentication()
        self.exchange_tokens()
        log.debug("Authentication successful.")

    def initialize_authentication(self):
        self._broker_connection.request(SaslHandshakeRequest.get_versions()[self.handshake_version](self.mechanism))
        response = SaslHandshakeResponse.get_versions()[self.handshake_version](self._broker_connection.response())
        if response.error_code != 0:
            if response.error_code == UnsupportedSaslMechanism.ERROR_CODE:
                msg = "Broker only supports sasl mechanisms {}, requested was {}"
                raise UnsupportedSaslMechanism(msg.format(",".join(response.mechanisms), self.mechanism))
            raise ERROR_CODES[response.error_code]("Authentication Handshake failed")

    def exchange_tokens(self):
        raise NotImplementedError()

    def send_token(self, token):
        log.debug("Seding auth token")
        if self.handshake_version == 0:
            req = FakeRequest(token)
        else:
            req = SaslAuthenticateRequest.get_versions()[self.auth_version](token)
        self._broker_connection.request(req)

    def receive_token(self):
        log.debug("Receiving auth token")
        if self.handshake_version == 0:
            return self._broker_connection.response_raw()

        data = self._broker_connection.response()
        response = SaslAuthenticateResponse.get_versions()[self.auth_version](data)
        if response.error_code != 0:
            raise ERROR_CODES[response.error_code](response.error_message)
        return response.auth_bytes

    def fetch_api_versions(self):
        log.debug("Fetch SASL authentication api versions.")
        self._broker_connection.request(ApiVersionsRequest())
        response = ApiVersionsResponse(self._broker_connection.response())
        self.handshake_version = response.api_versions[SaslHandshakeRequest.API_KEY].max
        self.auth_version = response.api_versions.get(SaslAuthenticateRequest.API_KEY, None)
        self.handshake_version = min(self.MAX_HANDSHAKE_VERSION, self.handshake_version)
        if self.auth_version is not None:
            self.auth_version = min(self.auth_version.max, self.MAX_AUTH_VERSION)
        log.debug("Determinded handshake api version {} and authenticate api version {}".format(
            self.handshake_version, self.auth_version
        ))

class ScramAuthenticator(BaseAuthenticator):
    """
    Authenticates with Kafka using the salted challenge response authentication mechanism.
    """

    MECHANISMS = {"SCRAM-SHA-256": ("sha256", hashlib.sha256), "SCRAM-SHA-512": ("sha512", hashlib.sha512)}

    def __init__(self, mechanism, user, password, security_protocol=None):
        """
        Create new ScramAuthenticator

        :param mechanism: The mechanism this authenticator is supposed to use.
        :type mechanism: str, one of 'SCRAM-SHA-256' or 'SCRAM-SHA-512'
        :param user: The user to authenticate as.
        :type user: str
        :param password: The user's password.
        :type password: str
        :param security_protocol: The security protocol determining the broker endpoint this
                                  authenticator is supposed to authenticate with.
                                  Only used for rdkafka based consumers and producers.
        """
        super(ScramAuthenticator, self).__init__(mechanism, security_protocol)
        self.nonce = None
        self.auth_message = None
        self.salted_password = None
        self.user = user
        self.password = password.encode()
        self.hashname, self.hashfunc = self.MECHANISMS[mechanism]
        self.mechanism = mechanism
        self.stored_key = None
        self.client_key = None
        self.client_signature = None
        self.client_proof = None
        self.server_key = None
        self.server_signature = None

    def first_message(self):
        self.nonce = str(uuid4()).replace("-", "")
        client_first_bare = "n={},r={}".format(self.user, self.nonce)
        self.auth_message = client_first_bare
        return "n,," + client_first_bare

    def process_server_first_message(self, server_first_message):
        self.auth_message += "," + server_first_message
        params = dict(pair.split("=", 1) for pair in server_first_message.split(","))
        server_nonce = params["r"]
        if not server_nonce.startswith(self.nonce):
            raise AuthenticationException("Server nonce, did not start with client nonce!")
        self.nonce = server_nonce
        self.auth_message += ",c=biws,r=" + self.nonce

        salt = base64.b64decode(params["s"].encode())
        iterations = int(params["i"])
        self.create_salted_password(salt, iterations)

        self.client_key = self.hmac(self.salted_password, b"Client Key")
        self.stored_key = self.hashfunc(self.client_key).digest()
        self.client_signature = self.hmac(self.stored_key, self.auth_message.encode())
        self.client_proof = xor_bytes(self.client_key, self.client_signature)
        self.server_key = self.hmac(self.salted_password, b"Server Key")
        self.server_signature = self.hmac(self.server_key, self.auth_message.encode())

    def hmac(self, key, msg):
        return hmac.new(key, msg, digestmod=self.hashfunc).digest()

    def create_salted_password(self, salt, iterations):
        self.salted_password = hashlib.pbkdf2_hmac(self.hashname, self.password, salt, iterations)

    def final_message(self):
        return "c=biws,r={},p={}".format(self.nonce, base64.b64encode(self.client_proof).decode())

    def process_server_final_message(self, server_final_message):
        params = dict(pair.split("=", 1) for pair in server_final_message.split(","))
        if self.server_signature != base64.b64decode(params["v"].encode()):
            raise AuthenticationException("Server sent wrong signature!")

    def get_rd_kafka_opts(self):
        return {
            "sasl.mechanisms": self.mechanism,
            "sasl.username": self.user,
            "sasl.password": self.password.decode(),
            "security.protocol": self.security_protocol,
        }

    def exchange_tokens(self):
        client_first = self.first_message()
        self.send_token(client_first.encode())

        server_first = self.receive_token().decode()
        self.process_server_first_message(server_first)

        client_final = self.final_message()
        self.send_token(client_final.encode())

        server_final = self.receive_token().decode()
        self.process_server_final_message(server_final)


class PlainAuthenticator(BaseAuthenticator):
    """
    Authenticates with kafka using the Plain mechanism. I.e. sending user and password in plaintext.
    """

    def __init__(self, user, password, security_protocol=None):
        """
        Create new PlainAuthenticator.

        :param user: The user to authenticate as.
        :type user: str
        :param password: The user's password.
        :type password: str
        :param security_protocol: The security protocol determining the broker endpoint this
                                  authenticator is supposed to authenticate with.
                                  Only used for rdkafka based consumers and producers.
        """
        super(PlainAuthenticator, self).__init__("PLAIN", security_protocol)
        self.user = user
        self.password = password

    def get_rd_kafka_opts(self):
        return {
            "sasl.mechanisms": self.mechanism,
            "sasl.username": self.user,
            "sasl.password": self.password,
            "security.protocol": self.security_protocol,
        }

    def exchange_tokens(self):
        self.send_token("\0".join([self.user, self.user, self.password]).encode())
        response = self.receive_token()
        if response != b"":
            raise AuthenticationException("Server sent unexpected response!")
