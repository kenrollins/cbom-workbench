"""The host's time source, as the kernel reports it: whether the clock is disciplined by a time
service, and the error the kernel estimates. Every ledger event carries a timestamp; a collector
or an assessor asking whether those can be trusted is asking this (NIST SP 800-53 AU-8).

Read with `adjtimex(2)` in its read-only form, which needs no privilege and works inside a
container, where it reports the host kernel's clock. No command is run and nothing is changed.
"""

from __future__ import annotations

import ctypes
import ctypes.util

STA_UNSYNC = 0x0040
STATES = {0: "ok", 1: "leap-insert", 2: "leap-delete", 3: "leap-in-progress", 4: "leap-occurred", 5: "unsynchronized"}


class _Timex(ctypes.Structure):
    # struct timex from <sys/timex.h>, 64-bit Linux; the trailing padding covers the reserved fields.
    _fields_ = [("modes", ctypes.c_uint), ("offset", ctypes.c_long), ("freq", ctypes.c_long),
                ("maxerror", ctypes.c_long), ("esterror", ctypes.c_long), ("status", ctypes.c_int),
                ("constant", ctypes.c_long), ("precision", ctypes.c_long), ("tolerance", ctypes.c_long),
                ("time_sec", ctypes.c_long), ("time_usec", ctypes.c_long), ("tick", ctypes.c_long),
                ("pad", ctypes.c_byte * 128)]


def time_source() -> dict:
    """`{"source": "adjtimex", "synchronized": bool, "state": ..., "max_error_us": n, "est_error_us": n}`,
    or `{"source": "unavailable", "synchronized": None, "reason": ...}` where the call cannot be made."""
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
        tx = _Timex()
        tx.modes = 0
        state = libc.adjtimex(ctypes.byref(tx))
        if state < 0:
            raise OSError(ctypes.get_errno(), "adjtimex refused")
    except Exception as e:  # a platform without the call is reported, not fatal
        return {"source": "unavailable", "synchronized": None, "reason": f"{type(e).__name__}: {e}"[:120]}
    return {"source": "adjtimex", "synchronized": not (tx.status & STA_UNSYNC) and state != 5,
            "state": STATES.get(state, str(state)), "max_error_us": int(tx.maxerror), "est_error_us": int(tx.esterror)}
