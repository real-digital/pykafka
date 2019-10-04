import os
import unittest
from uuid import uuid4

import pytest

from pykafka import KafkaClient, PlainAuthenticator, ScramAuthenticator
from pykafka.test.utils import get_cluster, stop_cluster
from pykafka.test.kafka_instance import SASL_USER, SASL_PASSWORD


kafka_version = os.environ.get('KAFKA_VERSION', '0.8.0')


class SaslIntegrationTests(unittest.TestCase):
    USE_RDKAFKA = False

    @classmethod
    def setUpClass(cls):
        cls.kafka = get_cluster()
        if cls.kafka.brokers_sssl is None:
            pytest.skip("Test-cluster doesn't advertise sasl ports.")

    @classmethod
    def tearDownClass(cls):
        stop_cluster(cls.kafka)

    @pytest.mark.parametrize('mechanism', ['PLAIN', 'SCRAM-SHA-256', 'SCRAM-SHA-512'])
    def test_roundtrip(self, mechanism):
        """Test producing then consuming

        This is mostly important to test the pykafka.rdkafka classes, which
        should be passed SASL settings during producer/consumer init.
        """
        if mechanism.startswith('SCRAM'):
            authenticator = ScramAuthenticator(mechanism, username=SASL_USER, password=SASL_PASSWORD)
        else:
            authenticator = PlainAuthenticator(username=SASL_USER, password=SASL_PASSWORD)

        client = KafkaClient(self.kafka.brokers_sasl, sasl_authenticator=authenticator,
                             broker_version=kafka_version)

        topic_name = uuid4().hex.encode()
        payload = uuid4().hex.encode()
        topic = client.topics[topic_name]

        producer = topic.get_producer(use_rdkafka=self.USE_RDKAFKA, sync=True)
        producer.produce(payload)

        consumer = topic.get_simple_consumer(use_rdkafka=self.USE_RDKAFKA,
                                             consumer_timeout_ms=5000)
        self.assertEqual(consumer.consume().value, payload)
