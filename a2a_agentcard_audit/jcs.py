"""RFC 8785 JSON Canonicalization Scheme (JCS)."""

import json
import math


def canonicalize(value):
    """Return the RFC 8785 canonical form of a JSON value as UTF-8 bytes."""
    return _serialize(value).encode("utf-8")


def _serialize(v):
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, (int, float)):
        return format_number(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(_serialize(x) for x in v) + "]"
    if isinstance(v, dict):
        for k in v:
            if not isinstance(k, str):
                raise TypeError("JSON object keys must be strings, got %r" % (k,))
        # RFC 8785 3.2.3: sort by UTF-16 code units, not code points.
        keys = sorted(v, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + _serialize(v[k]) for k in keys) + "}"
    raise TypeError("not a JSON value: %r" % (v,))


def format_number(x):
    """Serialize a number the way ECMAScript Number.prototype.toString does (RFC 8785 3.2.2.3)."""
    if isinstance(x, bool):
        raise TypeError("bool is not a number")
    if isinstance(x, int) and abs(x) <= 2 ** 53:
        return str(x)
    x = float(x)
    if math.isnan(x) or math.isinf(x):
        raise ValueError("NaN and Infinity are not valid JSON numbers")
    if x == 0:
        return "0"
    sign = "-" if x < 0 else ""
    r = repr(abs(x))
    mant, exp = (r.split("e") + ["0"])[:2]
    exp = int(exp)
    ip, fp = (mant.split(".") + [""])[:2]
    all_digits = ip + fp
    point = len(ip) + exp
    lead = len(all_digits) - len(all_digits.lstrip("0"))
    digits = all_digits.strip("0") or "0"
    n = point - lead  # value = 0.digits * 10**n
    k = len(digits)
    if k <= n <= 21:
        return sign + digits + "0" * (n - k)
    if 0 < n <= 21:
        return sign + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + digits
    e = n - 1
    tail = ("e+%d" % e) if e >= 0 else ("e-%d" % -e)
    return sign + (digits if k == 1 else digits[0] + "." + digits[1:]) + tail
