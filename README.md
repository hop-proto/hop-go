Hop
===

This repository contains Go implementations of the following:
- Cyclist duplex using keccak-1600f (working)
- Kravatte, using keccak-1600f (broken, not in progress)
- Hop transport, using Cyclist and AES (in progress)
- Hop channels (poc, not yet using transport)
- SSH replacement using Hop (drew)

Right now, the base package is `zmap.io/portal`, but that's not a final name, and we don't plan on hosting this as part of the ZMap organization.

See [ARCHITECTURE](./ARCHITECTURE.md) for details on how this project is
structured.
