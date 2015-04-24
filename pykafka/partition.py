"""
Author: Keith Bourgoin, Emmett Butler
"""
__license__ = """
Copyright 2015 Parse.ly, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
__all__ = ["Partition"]
import logging

import base
from .common import OffsetType
from .protocol import PartitionOffsetRequest

logger = logging.getLogger(__name__)


class Partition(base.BasePartition):
    """
    A Partition is an abstraction over the kafka concept of a partition.
    A kafka partition is a logical division of the logs for a topic. Its
    messages are totally ordered.
    """
    def __init__(self, topic, id_, leader, replicas, isr):
        """Instantiate a new Partition

        :param topic: The topic to which this Partition belongs
        :type topic: :class:`pykafka.topic.Topic`
        :param id_: The identifier for this partition
        :type id_: int
        :param leader: The broker that is currently acting as the leader for
            this partition.
        :type leader: :class:`pykafka.broker.Broker`
        :param replicas: A list of brokers containing this partition's replicas
        :type replicas: Iterable of :class:`pykafka.broker.Broker`
        :param isr: The current set of in-sync replicas for this partition
        :type isr: :class:`pykafka.broker.Broker`
        """
        self._id = id_
        self._leader = leader
        self._replicas = replicas
        self._isr = isr
        self._topic = topic

    def __repr__(self):
        return "<{}.{} at {} (id={})>".format(
            self.__class__.__module__,
            self.__class__.__name__,
            hex(id(self)),
            self._id,
        )

    @property
    def id(self):
        """The identifying int for this partition, unique within its topic"""
        return self._id

    @property
    def leader(self):
        """The broker currently acting as leader for this partition"""
        return self._leader

    @property
    def replicas(self):
        """The list of brokers currently holding replicas of this partition"""
        return self._replicas

    @property
    def isr(self):
        """The current list of in-sync replicas for this partition"""
        return self._isr

    @property
    def topic(self):
        """The topic to which this partition belongs"""
        return self._topic

    def fetch_offset_limit(self, offsets_before, max_offsets=1):
        """Use the Offset API to find a limit of valid offsets
            for this partition.

        :param offsets_before: Return an offset from before this timestamp (in
            milliseconds)
        :type offsets_before: int
        :param max_offsets: The maximum number of offsets to return
        :type max_offsets: int
        """
        request = PartitionOffsetRequest(
            self.topic.name, self.id, offsets_before, max_offsets
        )
        res = self._leader.request_offsets([request])
        return res.topics[self.topic.name][self._id][0]

    def latest_available_offsets(self):
        """Get the latest offset for this partition."""
        return self.fetch_offset_limit(OffsetType.LATEST)[self._id][0]

    def earliest_available_offsets(self):
        """Get the earliest offset for this partition."""
        return self.fetch_offset_limit(OffsetType.EARLIEST)[self._id][0]

    def __hash__(self):
        return hash((self.topic, self.id))

    def __eq__(self, other):
        return hash(self) == hash(other)

    def __ne__(self, other):
        return not self == other

    def update(self, brokers, metadata):
        """Update this partition with fresh metadata.

        :param brokers: Brokers on which partitions exist
        :type brokers: List of :class:`pykafka.broker.Broker`
        :param metadata: Metadata for the partition
        :type metadata: :class:`pykafka.protocol.PartitionMetadata`
        """
        try:
            # Check leader
            if metadata.leader != self._leader.id:
                logger.info('Updating leader for %s', self)
                self._leader = brokers[metadata.leader]
            # Check Replicas
            if sorted(r.id for r in self.replicas) != sorted(metadata.replicas):
                logger.info('Updating replicas list for %s', self)
                self._replicas = [brokers[b] for b in metadata.replicas]
            # Check In-Sync-Replicas
            if sorted(i.id for i in self.isr) != sorted(metadata.isr):
                logger.info('Updating in sync replicas list for %s', self)
                self._isr = [brokers[b] for b in metadata.isr]
        except KeyError:
            raise Exception("TODO: Type this exception")