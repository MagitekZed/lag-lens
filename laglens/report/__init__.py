"""Report generation: ``report.html``, export ZIPs and the sessions index.

* :mod:`laglens.report.build` — :class:`ReportBuilder` (live, every 30 s / on
  episode close / at shutdown) and :func:`rebuild` (offline ``--report DIR``).
* :mod:`laglens.report.export` — :func:`build_zip` / :func:`export_cli`.
* :mod:`laglens.report.sessions` — :func:`list_sessions`,
  :func:`session_summary`, :func:`rebuild_index`.

Everything here only *reads* the shared :class:`laglens.state.State` and the
session files through :class:`laglens.store.Store`; nothing is detected or
classified in this package (BUILD_PLAN §3.3, INTERFACES §10).
"""
