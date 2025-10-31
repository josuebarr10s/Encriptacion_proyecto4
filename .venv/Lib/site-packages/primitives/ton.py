# primitives/ton.py
from __future__ import annotations

from dataclasses import dataclass
from time import monotonic
from typing import Optional


@dataclass(slots=True)
class TON:
    """IEC-style TON (timer on-delay).

    Usage:
        t = TON(2.0)           # 2 seconds preset
        t.update(True)         # call each scan with enable signal
        if t.q: ...            # output goes True after preset elapses
    """
    preset: float                           # seconds
    _start: Optional[float] = None          # monotonic start time
    q: bool = False                         # done/output

    def reset(self) -> None:
        self._start = None
        self.q = False

    def update(self, enable: bool, now: Optional[float] = None) -> bool:
        """Update the timer; return output (q).

        Args:
            enable: input signal; when False, timer resets.
            now: optional monotonic time for testing; defaults to time.monotonic().
        """
        if not enable:
            self.reset()
            return self.q

        t = monotonic() if now is None else now
        if self._start is None:
            self._start = t
            self.q = False
            return self.q

        if (t - self._start) >= self.preset:
            self.q = True
        return self.q

    @property
    def elapsed(self) -> float:
        """Seconds since enable; 0 if not running."""
        if self._start is None:
            return 0.0
        t = monotonic()
        return max(0.0, t - self._start)
