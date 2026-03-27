"""
Overmind integration for tracing LLM calls.

Uses the overmind-sdk to auto-instrument OpenAI-compatible LLM clients.
Traces are sent to a local Overmind instance at localhost:8000.

Falls back to a mock tracer if the SDK is unavailable.
"""

import time
import logging
import os
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Optional

from packageguard.config import config

logger = logging.getLogger(__name__)

_overmind_initialized = False


def init_overmind():
    """Initialize Overmind SDK for auto-instrumentation of LLM calls."""
    global _overmind_initialized
    if _overmind_initialized:
        return True

    try:
        import overmind_sdk

        api_key = config.OVERMIND_API_KEY or os.getenv("OVERMIND_API_KEY", "")
        base_url = config.OVERMIND_BASE_URL

        if not api_key:
            logger.info(
                "OVERMIND_API_KEY not set. Start Overmind locally (make run), "
                "then copy the API token from the logs into .env"
            )
            return False

        overmind_sdk.init(
            overmind_api_key=api_key,
            service_name="packageguard",
            environment="development",
            providers=["openai"],  # OpenRouter uses OpenAI-compatible API
            overmind_base_url=base_url,
        )
        _overmind_initialized = True
        logger.info(f"Overmind SDK initialized — tracing to {base_url}")
        return True

    except ImportError:
        logger.warning("overmind-sdk not installed, using mock tracer")
        return False
    except Exception as e:
        logger.warning(f"Overmind init failed: {e}, using mock tracer")
        return False


# ─── Local trace recording (kept alongside Overmind for get_summary) ───

@dataclass
class TraceSpan:
    """A single traced LLM call (local record)."""
    name: str
    metadata: dict = field(default_factory=dict)
    trace_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    start_time: float = 0.0
    end_time: float = 0.0
    input_text: str = ""
    output_text: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    model: str = ""
    cost: float = 0.0
    error: Optional[str] = None
    feedback_rating: Optional[str] = None  # "up" or "down"
    feedback_note: str = ""

    def set_input(self, text: str):
        self.input_text = text

    def set_output(self, text: str):
        self.output_text = text

    def set_tokens(self, input_tokens: int, output_tokens: int):
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens
        self.cost = (input_tokens * 3 / 1_000_000) + (output_tokens * 15 / 1_000_000)

    def set_model(self, model: str):
        self.model = model

    def set_error(self, error: str):
        self.error = error

    @property
    def latency_ms(self) -> float:
        return (self.end_time - self.start_time) * 1000


class OvermindTracer:
    """
    Tracer that initializes the real Overmind SDK for auto-instrumentation
    and also keeps local trace records for get_summary().
    """

    def __init__(self):
        self.traces: list[TraceSpan] = []
        self.sdk_active = init_overmind()
        if self.sdk_active:
            logger.info("Overmind SDK active — LLM calls are auto-traced")
        else:
            logger.info("Running with local-only tracing (mock)")

    @contextmanager
    def trace(self, name: str, metadata: dict = None):
        """Record a local trace span. Overmind auto-instruments the actual LLM call."""
        span = TraceSpan(name=name, metadata=metadata or {})
        span.start_time = time.time()
        try:
            yield span
        except Exception as e:
            span.set_error(str(e))
            raise
        finally:
            span.end_time = time.time()
            self.traces.append(span)
            logger.debug(
                f"[TRACE] {name} | {span.latency_ms:.0f}ms | "
                f"{span.input_tokens}in/{span.output_tokens}out | "
                f"${span.cost:.4f} | model={span.model}"
            )

    def record_feedback(self, trace_id: str, rating: str, note: str = ""):
        """Record user feedback for a trace."""
        for t in self.traces:
            if t.trace_id == trace_id:
                t.feedback_rating = rating
                t.feedback_note = note
                logger.info(f"[FEEDBACK] {t.name} ({trace_id}): {rating} — {note}")
                return True
        logger.warning(f"[FEEDBACK] trace_id {trace_id} not found")
        return False

    def get_trace_by_id(self, trace_id: str) -> Optional[TraceSpan]:
        for t in self.traces:
            if t.trace_id == trace_id:
                return t
        return None

    def get_feedback_stats(self) -> dict:
        rated = [t for t in self.traces if t.feedback_rating]
        return {
            "total_calls": len(self.traces),
            "total_rated": len(rated),
            "thumbs_up": sum(1 for t in rated if t.feedback_rating == "up"),
            "thumbs_down": sum(1 for t in rated if t.feedback_rating == "down"),
        }

    def get_summary(self) -> dict:
        total_cost = sum(t.cost for t in self.traces)
        total_tokens = sum(t.input_tokens + t.output_tokens for t in self.traces)
        total_latency = sum(t.latency_ms for t in self.traces)
        feedback_stats = self.get_feedback_stats()
        return {
            "total_traces": len(self.traces),
            "total_cost_usd": round(total_cost, 4),
            "total_tokens": total_tokens,
            "total_latency_ms": round(total_latency, 1),
            "overmind_sdk_active": self.sdk_active,
            "feedback_stats": feedback_stats,
            "traces": [
                {
                    "name": t.name,
                    "trace_id": t.trace_id,
                    "latency_ms": round(t.latency_ms, 1),
                    "tokens": t.input_tokens + t.output_tokens,
                    "cost_usd": round(t.cost, 4),
                    "model": t.model,
                    "error": t.error,
                    "feedback_rating": t.feedback_rating,
                    **t.metadata,
                }
                for t in self.traces
            ],
        }


def get_tracer() -> OvermindTracer:
    """Get the tracer instance."""
    return OvermindTracer()


# Global tracer instance
tracer = get_tracer()
