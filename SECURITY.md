# Security

Phora is early public-preview software and has not completed a full public security process.

Please do not publish exploit details or weaponized proof-of-concepts in public issues. If private vulnerability reporting is enabled for the repository, use it. If it is not enabled yet, open a minimal public issue asking for security contact details without including sensitive technical details.

Before relying on Phora in hostile-input or long-running service environments, review:

- repository contents for third-party binaries, generated artifacts, and local research material
- MCP server behavior under hostile inputs
- memory ownership, concurrency, and long-running daemon safety
