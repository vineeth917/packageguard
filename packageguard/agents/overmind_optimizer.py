"""Overmind trace analysis and cost optimization recommendations."""

from __future__ import annotations

import asyncio
import json
import os
import urllib.error
import urllib.request
from typing import Any

from packageguard.tracing import tracer


class OvermindOptimizer:
    def __init__(self, base_url: str = "http://localhost:8000", api_key: str | None = None):
        self.base_url = os.getenv("OVERMIND_BASE_URL", base_url)
        self.api_key = api_key or os.getenv("OVERMIND_API_KEY")

    async def get_traces(self) -> list[dict]:
        """Fetch traces from Overmind API and merge with local session traces."""
        overmind_traces = []
        if self.api_key:
            url = f"{self.base_url.rstrip('/')}/api/v1/traces/list?project_id={self._project_id}"
            try:
                payload = await asyncio.to_thread(self._fetch_json, url)
                if isinstance(payload, dict):
                    raw_traces = payload.get("traces", [])
                    if raw_traces:
                        overmind_traces = self._normalize_traces(raw_traces)
                elif isinstance(payload, list) and payload:
                    overmind_traces = self._normalize_traces(payload)
            except Exception:
                pass

        # Always include local session traces (these have feedback state)
        local_traces = []
        summary = tracer.get_summary()
        if isinstance(summary, dict):
            local_traces = summary.get("traces", [])

        if not overmind_traces:
            return local_traces

        # Merge: Overmind traces first, then local traces not already in Overmind
        # Use trace_id to deduplicate
        seen_ids = {t.get("trace_id") for t in overmind_traces if t.get("trace_id")}
        merged = list(overmind_traces)
        for lt in local_traces:
            if lt.get("trace_id") and lt["trace_id"] not in seen_ids:
                merged.append(lt)
        return merged

    @property
    def _project_id(self) -> str:
        return os.getenv("OVERMIND_PROJECT_ID", "83f58635-a199-4f8e-81cb-dddf4267504a")

    def _normalize_traces(self, raw_traces: list[dict]) -> list[dict]:
        """Normalize Overmind OTLP trace format to our internal format."""
        normalized = []
        for t in raw_traces:
            attrs = t.get("SpanAttributes", {})
            if isinstance(attrs, str):
                try:
                    attrs = json.loads(attrs)
                except (json.JSONDecodeError, TypeError):
                    attrs = {}
            tokens = int(attrs.get("llm.usage.total_tokens", 0) or attrs.get("gen_ai.usage.total_tokens", 0) or 0)
            input_tokens = int(attrs.get("gen_ai.usage.input_tokens", 0) or 0)
            output_tokens = int(attrs.get("gen_ai.usage.output_tokens", 0) or 0)
            model = str(attrs.get("gen_ai.request.model", "") or "")
            name = t.get("Name", t.get("SpanName", "unknown"))
            # Claude Sonnet pricing: $3/M input + $15/M output
            cost = float(attrs.get("cost", 0) or 0)
            if cost == 0 and tokens > 0:
                cost = (input_tokens * 3.0 + output_tokens * 15.0) / 1_000_000
            duration_ns = int(t.get("DurationNano", 0) or 0)
            normalized.append({
                "name": name,
                "model": model,
                "tokens": tokens,
                "cost_usd": round(cost, 4),
                "span_id": t.get("SpanId", ""),
                "trace_id": t.get("TraceId", ""),
                "duration_ms": round(duration_ns / 1_000_000, 1),
            })
        return normalized

    def analyze_costs(self, traces: list[dict]) -> dict:
        """Analyze trace data and produce optimization recommendations."""
        recommendations: list[dict[str, Any]] = []
        total_cost = 0.0
        total_tokens = 0
        estimated_optimized_cost = 0.0

        for trace in traces:
            tokens = int(trace.get("tokens", 0) or 0)
            model = str(trace.get("model", "") or "")
            name = str(trace.get("name", "") or "")
            cost = float(trace.get("cost_usd", 0) or 0)
            total_cost += cost
            total_tokens += tokens
            projected_cost = cost

            if "metadata" in name.lower() and "sonnet" in model.lower():
                savings = round(cost * 0.90, 4)
                projected_cost = max(projected_cost - savings, 0.0)
                recommendations.append(
                    {
                        "type": "model_downgrade",
                        "call_name": name,
                        "current_model": model,
                        "suggested_model": "claude-haiku-4-5-20251001",
                        "estimated_savings_pct": 90,
                        "estimated_savings_usd": savings,
                        "reason": "Metadata checks are structured lookups, don't need advanced reasoning",
                    }
                )

            if tokens > 2000:
                savings = round(projected_cost * 0.40, 4)
                projected_cost = max(projected_cost - savings, 0.0)
                recommendations.append(
                    {
                        "type": "prompt_optimization",
                        "call_name": name,
                        "current_tokens": tokens,
                        "estimated_reduction_pct": 40,
                        "estimated_savings_usd": savings,
                        "reason": "Large code snippets can be trimmed to only suspicious functions",
                    }
                )

            estimated_optimized_cost += projected_cost

        total_cost = round(total_cost, 4)
        estimated_optimized_cost = round(estimated_optimized_cost, 4)
        savings_pct = round(
            ((total_cost - estimated_optimized_cost) / total_cost * 100) if total_cost else 0.0,
            1,
        )

        return {
            "total_cost": total_cost,
            "total_calls": len(traces),
            "total_tokens": total_tokens,
            "recommendations": recommendations,
            "estimated_optimized_cost": estimated_optimized_cost,
            "estimated_savings_pct": savings_pct,
        }

    def format_report(self, analysis: dict) -> str:
        """Format the optimization report for terminal display."""
        lines = [
            "[bold cyan]🧠 Overmind Optimization Report[/bold cyan]",
            (
                f"Total LLM cost: ${analysis.get('total_cost', 0):.3f} "
                f"across {analysis.get('total_calls', 0)} calls"
            ),
        ]

        for index, recommendation in enumerate(analysis.get("recommendations", []), start=1):
            if recommendation.get("type") == "model_downgrade":
                lines.append(
                    "Recommendation "
                    f"{index}: Switch {recommendation.get('call_name')} from "
                    f"{recommendation.get('current_model')} to "
                    f"{recommendation.get('suggested_model')} → save "
                    f"{recommendation.get('estimated_savings_pct')}% "
                    f"(${recommendation.get('estimated_savings_usd', 0):.2f})"
                )
            else:
                lines.append(
                    "Recommendation "
                    f"{index}: Trim code snippets in {recommendation.get('call_name')} → "
                    f"reduce tokens by {recommendation.get('estimated_reduction_pct')}%"
                )

        lines.append(
            "Projected optimized cost: "
            f"${analysis.get('estimated_optimized_cost', 0):.3f} "
            f"({analysis.get('estimated_savings_pct', 0):.0f}% reduction)"
        )
        return "\n".join(lines)

    def _get_jwt(self) -> str:
        """Login to Overmind and return JWT token."""
        url = f"{self.base_url.rstrip('/')}/api/v1/iam/users/login"
        data = json.dumps({"email": "admin", "password": "admin"}).encode()
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read().decode()).get("access_token", "")
        except Exception:
            return ""

    def _fetch_json(self, url: str) -> Any:
        # Try JWT auth first (Overmind requires it)
        token = self._get_jwt()
        if not token:
            token = self.api_key or ""
        request = urllib.request.Request(url)
        request.add_header("Authorization", f"Bearer {token}")
        request.add_header("Accept", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Failed to fetch Overmind traces from {url}: {exc}") from exc

    async def submit_feedback(self, span_id: str, rating: str = "up",
                               feedback_type: str = "agent", text: str = "") -> dict:
        """Submit feedback on a span to Overmind."""
        url = f"{self.base_url.rstrip('/')}/api/v1/spans/{span_id}/feedback"
        token = await asyncio.to_thread(self._get_jwt)
        if not token:
            return {"error": "Failed to authenticate with Overmind"}
        data = json.dumps({
            "feedback_type": feedback_type,
            "rating": rating,
            "text": text,
        }).encode()
        req = urllib.request.Request(url, data=data, method="PATCH")
        req.add_header("Authorization", f"Bearer {token}")
        req.add_header("Content-Type", "application/json")
        try:
            result = await asyncio.to_thread(
                lambda: urllib.request.urlopen(req, timeout=10).read().decode()
            )
            return json.loads(result) if result else {"status": "ok"}
        except Exception as exc:
            return {"error": str(exc)}

    async def get_spans(self) -> list[dict]:
        """Get span IDs from Overmind traces."""
        traces = await self.get_traces()
        spans = []
        for t in traces:
            if isinstance(t, dict):
                span_id = t.get("span_id") or t.get("id") or ""
                if span_id:
                    spans.append({"span_id": span_id, "name": t.get("name", ""), "model": t.get("model", "")})
        return spans
