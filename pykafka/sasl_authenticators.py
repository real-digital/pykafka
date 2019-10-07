import base64
import hashlib
import hmac
import logging
import struct
from uuid import uuid4

import six

from .exceptions import AuthenticationException, ERROR_CODES, UnsupportedSaslMechanism
from .protocol import (
    SaslHandshakeRequest,
    SaslHandshakeResponse,
    ApiVersionsRequest,
    ApiVersionsResponse,
    SaslAuthenticateRequest,
    SaslAuthenticateResponse,
)

log = logging.getLogger(__name__)


if six.PY2:
    def xor_bytes(left, right):
        return bytearray(ord(lb) ^ ord(rb) for lb, rb in zip(left, right))
else:
    def xor_bytes(left, right):
        return bytes(lb ^ rb for lb, rb in zip(left, right))


class BytesWrapper:
    """
    Class that implements :meth:`get_bytes` and wraps some payload so it can be used for
    :meth:`connection.BrokerConnection.request` during legacy sasl authentication sequence.
    """

    def __init__(self, payload):
        """
        Create a new FakeRequest.

        :param payload: The payload to wrap
        :type payload: bytes
        """
        self.payload = payload

    def get_bytes(self):
        return struct.pack("!i", len(self.payload)) + self.payload


class BaseAuthenticator:
    """
    Base class for authentication mechanisms.
    Subclasses are supposed to implement:
     1. :meth:`BaseAuthenticator.get_rd_kafka_opts` which should return a dictionary
        whose items will be appended to the config given to librdkafka consumers and producers.
     2. :meth:`BaseAuthenticator.exchange_tokens` which is supposed to use
        :meth:`BaseAuthenticator.send_and_receive` to send and receive the byte strings necessary to authenticate
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
        """
        Creates the config entries necessary for librdkafka to successfully authenticate with the broker.

        :return: Dictionary to enrich config for librdkafka based consumers and producers.
        """
        raise NotImplementedError()

    def authenticate(self, broker_connection):
        """
        Runs the authentication sequence on the given broker connection.

        .. warning::
           This is not thread safe!

        :param broker_connection: The broker connection to authenticate with.
        :type broker_connection: :class:`pykafka.connection.BrokerConnection`
        """
        self._broker_connection = broker_connection
        if self.handshake_version is None:
            self._fetch_api_versions()
        log.debug(
            "Authenticating to {}:{} using mechanism {}.".format(
                self._broker_connection.host, self._broker_connection.port, self.mechanism
            )
        )
        self._initialize_authentication()
        self.exchange_tokens()
        log.debug("Authentication successful.")

    def _initialize_authentication(self):
        """
        Initializes the authentication sequence.
        """
        self._broker_connection.request(SaslHandshakeRequest.get_versions()[self.handshake_version](self.mechanism))
        response = SaslHandshakeResponse.get_versions()[self.handshake_version](self._broker_connection.response())
        if response.error_code != 0:
            if response.error_code == UnsupportedSaslMechanism.ERROR_CODE:
                msg = "Broker only supports sasl mechanisms {}, requested was {}"
                raise UnsupportedSaslMechanism(msg.format(",".join(response.mechanisms), self.mechanism))
            raise ERROR_CODES[response.error_code]("Authentication Handshake failed")

    def exchange_tokens(self):
        """
        Runs the authentication sequence. Implementation varies among SASL mechanism and has to be supplied by
        subclasses. See also :meth:`PlainAuthenticator.exchange_tokens` or :meth:`ScramAuthenticator.exchange_tokens`
        for exemplary implementations.
        """
        raise NotImplementedError()

    def send_and_receive(self, token):
        """
        Sends the given token to the broker and receives the brokers response.
        This will automatically use the appropriate mechanism to do so.
        I.e. use SaslAuthenticateRequest if the server supports it or just send the bytes directly if it doesn't.

        :param token: The token to be sent to the broker.
        :type token: bytes
        :return: bytes, the servers response
        """
        self._send_token(token)
        return self._receive_token()

    def _send_token(self, token):
        log.debug("Seding auth token")
        if self.handshake_version == 0:
            req = BytesWrapper(token)
        else:
            req = SaslAuthenticateRequest.get_versions()[self.auth_version](token)
        self._broker_connection.request(req)

    def _receive_token(self):
        log.debug("Receiving auth token")
        if self.handshake_version == 0:
            return self._broker_connection.response_raw()

        data = self._broker_connection.response()
        response = SaslAuthenticateResponse.get_versions()[self.auth_version](data)
        if response.error_code != 0:
            raise ERROR_CODES[response.error_code](response.error_message)
        return response.auth_bytes

    def _fetch_api_versions(self):
        """
        The api version request can be run without authentication in order to determine which authentication api
        versions to use. That's what this method does.
        """
        log.debug("Fetch SASL authentication api versions.")
        self._broker_connection.request(ApiVersionsRequest())
        response = ApiVersionsResponse(self._broker_connection.response())

        self.handshake_version = response.api_versions[SaslHandshakeRequest.API_KEY].max
        self.auth_version = response.api_versions.get(SaslAuthenticateRequest.API_KEY, None)

        self.handshake_version = min(self.MAX_HANDSHAKE_VERSION, self.handshake_version)
        if self.auth_version is not None:
            self.auth_version = min(self.auth_version.max, self.MAX_AUTH_VERSION)
        log.debug(
            "Determinded handshake api version {} and authenticate api version {}".format(
                self.handshake_version, self.auth_version
            )
        )


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

    def client_first_message(self):
        """
        Create and return the client first message. This will also reset all internal variables.
        :return: str, the client first message
        """
        self.nonce = str(uuid4()).replace("-", "")
        client_first_bare = "n={},r={}".format(self.user, self.nonce)
        self.auth_message = client_first_bare
        return "n,," + client_first_bare

    def process_server_first_message(self, server_first_message):
        """
        Parse and process server first message, this will extract all necessary information from the server's first
        response such as iteration count or salt and use it to prepare the client final message.

        :param server_first_message: The first message sent by the server
        :type server_first_message: str
        """
        self.auth_message += "," + server_first_message
        params = dict(pair.split("=", 1) for pair in server_first_message.split(","))
        server_nonce = params["r"]
        if not server_nonce.startswith(self.nonce):
            raise AuthenticationException("Server nonce, did not start with client nonce!")
        self.nonce = server_nonce
        self.auth_message += ",c=biws,r=" + self.nonce

        salt = base64.b64decode(params["s"].encode())
        iterations = int(params["i"])
        self._create_salted_password(salt, iterations)

        self.client_key = self._hmac(self.salted_password, b"Client Key")
        self.stored_key = self.hashfunc(self.client_key).digest()
        self.client_signature = self._hmac(self.stored_key, self.auth_message.encode())
        self.client_proof = xor_bytes(self.client_key, self.client_signature)
        self.server_key = self._hmac(self.salted_password, b"Server Key")
        self.server_signature = self._hmac(self.server_key, self.auth_message.encode())

    def _hmac(self, key, msg):
        """
        Run the hmac algorithm on `key` and `msg` using the appropriate digest method for the configures scram
        mechanism.
        :param key: The key for the hmac algorithm
        :type key: bytes
        :param msg: The message for the hmac algorithm
        :type msg: bytes
        :return: bytes, the result of applying hmac on `key` and `msg`
        """
        return hmac.new(key, msg, digestmod=self.hashfunc).digest()

    def _create_salted_password(self, salt, iterations):
        self.salted_password = hashlib.pbkdf2_hmac(self.hashname, self.password, salt, iterations)

    def client_final_message(self):
        """
        Create and return the client final message.
        :return: str, the client final message
        """
        return "c=biws,r={},p={}".format(self.nonce, base64.b64encode(self.client_proof).decode())

    def process_server_final_message(self, server_final_message):
        """
        Parse and process server final message. This will run validation on the server's response to make sure that
        everything is all right.

        :param server_final_message: The first message sent by the server
        :type server_final_message: str
        """
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
        client_first = self.client_first_message()
        server_first = self.send_and_receive(client_first.encode()).decode()
        self.process_server_first_message(server_first)

        client_final = self.client_final_message()
        server_final = self.send_and_receive(client_final.encode()).decode()
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
        token = "\0".join([self.user, self.user, self.password]).encode()
        response = self.send_and_receive(token)
        if response != b"":
            raise AuthenticationException("Server sent unexpected response!")
