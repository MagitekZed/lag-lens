"""HTTP server, SSE broadcaster and series builder for the Lag Lens dashboard.

* :mod:`laglens.server.http` — ``serve(ctx)`` (BUILD_PLAN §3.4 routes)
* :mod:`laglens.server.sse` — ``Broadcaster`` fan-out of ``state.publish``
* :mod:`laglens.server.series` — ``build_series`` (the ``GET /api/series`` body)
"""
