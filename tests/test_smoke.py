#!/usr/bin/env python3
"""Minimal smoke tests for sushCore components."""

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sush.transport.protocol_hopper import ProtocolHopper
from sush.transport.metadata_channels import MetadataChannels


class SmokeTests(unittest.TestCase):
    def test_protocol_hopper_sequence(self):
        hopper = ProtocolHopper()
        sequence = hopper.create_hop_sequence("smoke_seq", num_hops=4)
        self.assertEqual(len(sequence.ports), 4)
        self.assertEqual(len(sequence.protocols), 4)
        self.assertEqual(len(sequence.timing_intervals), 4)
        self.assertTrue(all(isinstance(port, int) for port in sequence.ports))

    def test_metadata_channel_switch(self):
        channels = MetadataChannels()
        self.assertIn('ttl', channels.channels)
        self.assertIn('ip_id', channels.channels)
        channels.switch_channel('ip_id')
        self.assertEqual(channels.active_channel, 'ip_id')


if __name__ == "__main__":
    unittest.main()
