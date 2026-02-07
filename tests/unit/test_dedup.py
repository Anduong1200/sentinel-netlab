from datetime import UTC, datetime, timedelta

from common.scoring.types import Severity
from controller.dedup.policy import TriagePolicy
from controller.dedup.store import EventState


def test_suppression():
    """Verify suppression window logic."""
    policy = TriagePolicy(suppression_window_seconds=100)

    # 1. New Event (No State) -> Emit
    assert policy.should_emit(None, None, Severity.LOW, 10.0) is True

    # 2. Recent Emit (Inside Window) -> Suppress
    now = datetime.now(UTC)
    state = EventState(
        first_seen=now,
        last_seen=now,
        last_emitted=now,
        count=1,
        max_severity=Severity.LOW,
        max_risk_score=10.0,
    )
    assert policy.should_emit(None, state, Severity.LOW, 10.0) is False

    # 3. Old Emit (Outside Window) -> Emit
    old_state = EventState(
        first_seen=now,
        last_seen=now,
        last_emitted=now - timedelta(seconds=200),
        count=1,
        max_severity=Severity.LOW,
        max_risk_score=10.0,
    )
    assert policy.should_emit(None, old_state, Severity.LOW, 10.0) is True


def test_escalation():
    """Verify severity escalation bypasses suppression."""
    policy = TriagePolicy(suppression_window_seconds=100)
    now = datetime.now(UTC)

    # Suppressed state (Low Risk)
    state = EventState(
        first_seen=now,
        last_seen=now,
        last_emitted=now,
        count=1,
        max_severity=Severity.LOW,
        max_risk_score=10.0,
    )

    # New High Risk finding -> Emit (Bypass)
    assert policy.should_emit(None, state, Severity.HIGH, 80.0) is True
