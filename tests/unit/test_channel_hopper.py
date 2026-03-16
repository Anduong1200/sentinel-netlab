import time
from unittest.mock import MagicMock, patch

from sensor.channel_hopper import ChannelHopper


class TestChannelHopper:
    def test_round_robin_hopping(self):
        mock_driver = MagicMock()
        mock_driver.set_channel.return_value = True
        channels = [1, 6, 11]

        hopper = ChannelHopper(
            driver=mock_driver,
            channels=channels,
            dwell_ms=10,
            settle_ms=1,
            adaptive=False,
        )

        assert hopper.get_current_channel() == 1

        hopper.start()
        # Allow hopper to run a few loops
        time.sleep(0.1)
        hopper.stop()

        # It should have called set_channel multiple times
        assert mock_driver.set_channel.call_count > 1

        # Check that it called the channels in sequence
        calls = [call[0][0] for call in mock_driver.set_channel.call_args_list]
        for i in range(len(calls) - 1):
            current_ch = calls[i]
            next_ch = calls[i + 1]
            current_idx = channels.index(current_ch)
            expected_next_idx = (current_idx + 1) % len(channels)
            assert next_ch == channels[expected_next_idx]

    @patch("random.random")
    def test_adaptive_hopping(self, mock_random):
        mock_driver = MagicMock()
        mock_driver.set_channel.return_value = True
        channels = [1, 6, 11]

        hopper = ChannelHopper(
            driver=mock_driver,
            channels=channels,
            dwell_ms=10,
            settle_ms=1,
            adaptive=True,
        )

        # Initially, all activities are equal (1.0).
        # We simulate high activity on channel 6
        hopper.record_activity(6, 100)

        # Mock random to always return a value that falls into channel 6's cumulative probability bucket
        # Total weight will be ~31.4. Channel 1 = 1.0, Channel 6 = 30.7, Channel 11 = 1.0
        # Passing 0.5 * total will fall into channel 6.
        mock_random.return_value = 0.5

        hopper.start()
        time.sleep(0.1)
        hopper.stop()

        assert mock_driver.set_channel.call_count > 0
        calls = [call[0][0] for call in mock_driver.set_channel.call_args_list]

        # In adaptive mode with mocked random, it should overwhelmingly favor channel 6
        assert all(ch == 6 for ch in calls)
