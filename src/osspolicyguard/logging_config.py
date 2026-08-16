from __future__ import annotations

import json
import logging
import re

__all__ = ["configure_logging", "get_logger", "RedactingFilter", "StructuredFormatter"]


class RedactingFilter(logging.Filter):
    _PATTERNS: list[re.Pattern] = [
        re.compile(r"ghp_[A-Za-z0-9]{36}"),
        re.compile(r"glpat-[A-Za-z0-9_-]{20}"),
        re.compile(r"(api_key|nvd_key|token|password|secret)\s*[=:]\s*\S+"),
        re.compile(r"Authorization:\s*Bearer\s+\S+"),
        re.compile(r"Bearer\s+[A-Za-z0-9._-]{20,}"),
    ]

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = self._redact(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    k: (self._redact(v) if isinstance(v, str) else v)
                    for k, v in record.args.items()
                }
            elif isinstance(record.args, tuple):
                record.args = tuple(
                    self._redact(a) if isinstance(a, str) else a
                    for a in record.args
                )
            else:
                # Single non-tuple arg: only redact if it is a string so that
                # numeric format specifiers (%d, %f) are not coerced to str.
                if isinstance(record.args, str):
                    record.args = self._redact(record.args)
        return True

    def _redact(self, text: str) -> str:
        for pattern in self._PATTERNS:
            text = pattern.sub("[REDACTED]", text)
        return text


class StructuredFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        d: dict = {
            "ts": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for field in ("request_id", "provider", "latency_ms", "retry_count", "outcome"):
            value = getattr(record, field, None)
            if value is not None:
                d[field] = value
        return json.dumps(d, separators=(",", ":"))


def configure_logging(level: str = "INFO", json_output: bool = False) -> None:
    """Configure the root logger with secret redaction on every output handler.

    Idempotent: calling more than once replaces any handler added by a previous
    call to this function (identified by the ``_opg_handler`` attribute) rather
    than adding duplicates.
    """
    redactor = RedactingFilter()
    handler = logging.StreamHandler()
    # Attach the redaction filter to the handler so that records emitted by
    # child loggers that propagate to this handler are always scrubbed,
    # regardless of which logger they originate from.
    handler.addFilter(redactor)
    handler._opg_handler = True  # type: ignore[attr-defined]

    if json_output:
        handler.setFormatter(StructuredFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-8s %(name)s: %(message)s")
        )

    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Remove any previously registered OPG handler to stay idempotent.
    root.handlers = [h for h in root.handlers if not getattr(h, "_opg_handler", False)]
    root.addHandler(handler)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
