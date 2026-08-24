# ADR-0013 - Keep v2 profiles separate and experimental

Status: Accepted

The v2 core validates generic framing and accepts unknown types. Native semantics
therefore live in separate profiles. Profile 0 is freeze-readiness work, not a
wire freeze; independent vectors, authentication, and deployment remain gates.
