Hop
===

This repository contains Go implementations of the following:
- Cyclist duplex using keccak-1600f
- Kravatte, using keccak-1600f
- Hop transport, using Cyclist and Kravatte SANSE
- Hop channels (WIP)
- SSH replacement using Hop (WIP)

Right now, the base package is `zmap.io/portal`, but that's not a final name,
and we don't plan on hosting this as part of the ZMap organization.

See [ARCHITECTURE](./ARCHITECTURE.md) for details on how this project is
structured.
