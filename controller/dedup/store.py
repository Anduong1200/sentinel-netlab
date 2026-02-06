
from dataclasses import dataclass
from datetime import UTC, datetime

from common.scoring.types import Severity


@dataclass
class EventState:
    first_seen: datetime
    last_seen: datetime
    last_emitted: datetime # Track when we actually sent an alert
    count: int
    max_severity: Severity
    max_risk_score: float

class EventStore:
    """
    Stores state of active/recent detection events.
    Currently In-Memory. In production, use Redis.
    """

    def __init__(self):
        self._store: dict[str, EventState] = {}

    def get_state(self, fingerprint: str) -> EventState | None:
        return self._store.get(fingerprint)

    def update_state(self, fingerprint: str, severity: Severity, risk_score: float, emitted: bool = False) -> EventState:
        now = datetime.now(UTC)
        state = self._store.get(fingerprint)

        if not state:
            state = EventState(
                first_seen=now,
                last_seen=now,
                last_emitted=now if emitted else datetime.min.replace(tzinfo=UTC),
                count=1,
                max_severity=severity,
                max_risk_score=risk_score
            )
            self._store[fingerprint] = state
        else:
            state.last_seen = now
            state.count += 1
            if emitted:
                state.last_emitted = now

            if risk_score > state.max_risk_score:
                state.max_risk_score = risk_score
                state.max_severity = severity

            self._store[fingerprint] = state

        return state
