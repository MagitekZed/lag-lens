"""Probe implementations.

* :mod:`laglens.probes.icmp` — echo packet building/parsing for the unprivileged
  DGRAM ICMP sockets (v4 + v6), TTL-exceeded parsing and the Linux errqueue
  helpers used by the tracer;
* :mod:`laglens.probes.pingbin` — the per-target ``ping`` subprocess backend
  used when a family's ICMP socket cannot be opened;
* :mod:`laglens.probes.path` — path discovery (native TTL probing + command
  fallbacks), hop roles and the episode sweep.

The scheduling loop that drives the ICMP sockets lives in
:mod:`laglens.engine.scheduler`.
"""
