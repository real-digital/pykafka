import pytest
from uuid import uuid4

from pykafka import KafkaClient
try:
    from pykafka.rdkafka import _rd_kafka
    RDKAFKA = True
except ImportError:
    RDKAFKA = False  # C extension not built


@pytest.mark.skipif(not RDKAFKA, reason="C extension for librdkafka not built.")
def test_sasl_roundtrip_rdkafka(sasl_kafka, authenticator, kafka_version):
    client = KafkaClient(sasl_kafka.brokers_sasl, sasl_authenticator=authenticator,
                         broker_version='.'.join(str(v) for v in kafka_version))

    topic_name = uuid4().hex.encode()
    payload = uuid4().hex.encode()
    topic = client.topics[topic_name]

    producer = topic.get_producer(use_rdkafka=True, sync=True)
    producer.produce(payload)

    consumer = topic.get_simple_consumer(use_rdkafka=True, consumer_timeout_ms=5000)
    assert consumer.consume().value == payload