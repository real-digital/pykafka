import logging
import os
import pytest
from pykafka.test.utils import get_cluster, stop_cluster
from pykafka import PlainAuthenticator, ScramAuthenticator
from pykafka.test.kafka_instance import SASL_USER, SASL_PASSWORD

logging.basicConfig(level=logging.DEBUG)

KAFKA_VERSION = tuple(int(v) for v in os.environ.get('KAFKA_VERSION', '0.8.0').split('.'))


@pytest.fixture
def kafka_version():
    return KAFKA_VERSION


@pytest.fixture(
    params=[
        pytest.param(
            "PLAIN", marks=pytest.mark.skipif(KAFKA_VERSION < (0, 10), reason="Requires KAFKA_VERSION >= 0.10")
        ),
        pytest.param(
            "SCRAM-SHA-256",
            marks=pytest.mark.skipif(KAFKA_VERSION < (0, 10, 2), reason="Requires KAFKA_VERSION >= 0.10.2"),
        ),
        pytest.param(
            "SCRAM-SHA-512",
            marks=pytest.mark.skipif(KAFKA_VERSION < (0, 10, 2), reason="Requires KAFKA_VERSION >= 0.10.2"),
        ),
    ]
)
def authenticator(request):
    sasl_mechanism = request.param
    if sasl_mechanism.startswith('SCRAM'):
        return ScramAuthenticator(sasl_mechanism, user=SASL_USER, password=SASL_PASSWORD)
    else:
        return PlainAuthenticator(user=SASL_USER, password=SASL_PASSWORD)


@pytest.fixture(scope='session')
def kafka():
    kafka = get_cluster()
    yield kafka
    stop_cluster(kafka)


@pytest.fixture
def sasl_kafka(kafka):
    if not kafka.brokers_sasl:
        pytest.skip("Cluster has no SASL endpoint.")
    else:
        yield kafka