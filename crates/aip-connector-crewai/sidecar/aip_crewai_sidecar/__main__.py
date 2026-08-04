"""Command-line entry point for the AIP CrewAI sidecar."""

from __future__ import annotations

import os

import uvicorn


def main() -> None:
    """Run the sidecar using environment-owned configuration."""

    uvicorn.run(
        "aip_crewai_sidecar.app:create_app",
        factory=True,
        host=os.environ.get("AIP_CREWAI_HOST", "0.0.0.0"),
        port=int(os.environ.get("AIP_CREWAI_PORT", "8090")),
        proxy_headers=False,
        server_header=False,
    )


if __name__ == "__main__":
    main()
