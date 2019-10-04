from uuid import uuid4

from pykafka import KafkaClient


def test_sasl_roundtrip(sasl_kafka, authenticator, kafka_version):
    """Test producing then consuming

    This is mostly important to test the pykafka.rdkafka classes, which
    should be passed SASL settings during producer/consumer init.
    """
    client = KafkaClient(sasl_kafka.brokers_sasl, sasl_authenticator=authenticator, broker_version=kafka_version)

    topic_name = uuid4().hex.encode()
    payload = uuid4().hex.encode()
    topic = client.topics[topic_name]

    producer = topic.get_producer(use_rdkafka=False, sync=True)
    producer.produce(payload)

    consumer = topic.get_simple_consumer(use_rdkafka=False, consumer_timeout_ms=5000)
    assert consumer.consume().value == payload