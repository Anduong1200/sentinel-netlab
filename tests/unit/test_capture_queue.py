import multiprocessing as mp
import time
from unittest.mock import MagicMock, patch

from sensor.capture_queue import (
    CaptureConsumer,
    CaptureProducer,
    ProducerConsumerEngine,
)


class TestCaptureProducer:
    @patch("subprocess.run")
    @patch("subprocess.Popen")
    def test_run_producer(self, mock_popen, mock_run):
        """Test CaptureProducer loop logic with mock output"""
        q = mp.Queue()
        stop_event = mp.Event()

        # Setup mock subprocess
        mock_process = MagicMock()

        # Make readline return packets and then raise to simulate blocking/end
        def mock_readline():
            if not getattr(mock_readline, "called", False):
                mock_readline.called = True
                return b"packet1\n"
            time.sleep(0.05)
            return b""

        mock_process.stdout.readline.side_effect = mock_readline
        mock_popen.return_value = mock_process

        producer = CaptureProducer(
            packet_queue=q,
            interface="wlan0mon",
            channels=[1],
            dwell_time=0.1,
            stop_event=stop_event,
        )

        def set_stop():
            time.sleep(0.1)
            stop_event.set()

        import threading

        t = threading.Thread(target=set_stop)
        t.start()

        producer.run()
        t.join()

        # Ensure packets were put into queue
        assert q.qsize() > 0
        pkt = q.get()
        assert pkt["data"] == b"packet1"
        assert "channel" in pkt

    @patch("subprocess.run")
    def test_enable_monitor_mode(self, mock_run):
        q = mp.Queue()
        stop_event = mp.Event()
        producer = CaptureProducer(
            q, "wlan0", channels=[1, 6, 11], stop_event=stop_event
        )

        res = producer.enable_monitor_mode()
        assert res is True
        assert mock_run.call_count == 3
        mock_run.assert_any_call(
            ["ip", "link", "set", "wlan0", "down"], check=True, timeout=5
        )


class TestCaptureConsumer:
    def test_consumer_processing(self):
        q = mp.Queue()
        stop_event = mp.Event()

        callback_mock = MagicMock()

        consumer = CaptureConsumer(
            packet_queue=q,
            stop_event=stop_event,
            packet_callback=callback_mock,
            batch_size=2,
            batch_timeout=0.1,
        )

        # Put 3 packets in queue
        q.put({"data": b"1"})
        q.put({"data": b"2"})
        q.put({"data": b"3"})

        # Run consumer in a thread
        consumer.start()

        # Let it process
        time.sleep(0.2)

        # Stop it
        stop_event.set()
        consumer.join(timeout=1.0)

        # Verify callback was called for each packet
        assert callback_mock.call_count == 3
        assert consumer.stats["packets_processed"] == 3


class TestProducerConsumerEngine:
    @patch("sensor.capture_queue.CaptureProducer")
    @patch("sensor.capture_queue.CaptureConsumer")
    def test_engine_lifecycle(self, mock_consumer_cls, mock_producer_cls):
        mock_producer = MagicMock()
        mock_producer_cls.return_value = mock_producer

        mock_consumer = MagicMock()
        mock_consumer_cls.return_value = mock_consumer

        engine = ProducerConsumerEngine(interface="wlan0")

        assert not engine.is_capturing

        # Start
        started = engine.start(packet_callback=lambda x: None)
        assert started is True
        assert engine.is_capturing is True

        mock_producer.start.assert_called_once()
        mock_consumer.start.assert_called_once()

        # Stop
        engine.stop()
        assert engine.is_capturing is False
        assert engine.stop_event.is_set()
        mock_producer.join.assert_called_once()
        mock_consumer.join.assert_called_once()
