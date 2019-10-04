import platform

import pytest

from tests.pykafka import test_sasl


@pytest.mark.skipif(platform.python_implementation() == "PyPy",
                    reason="We pass PyObject pointers as msg_opaques for "
                           "delivery callbacks, which is unsafe on PyPy.")
class TestRdKafkaSasl(test_sasl.SaslIntegrationTests):
    USE_RDKAFKA = True
