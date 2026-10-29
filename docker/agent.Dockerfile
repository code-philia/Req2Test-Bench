# A base for the image of an agent that runs in a container (docs/agents.md,
# "Agents in containers"). Build it, then install your agent on top:
#
#   docker build -t r2t-agent-base -f docker/agent.Dockerfile docker
#
#   FROM r2t-agent-base
#   RUN <install your agent>
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends bash bubblewrap ca-certificates git \
       python3-minimal \
    && rm -rf /var/lib/apt/lists/* \
    && echo 'PATH="/r2t-rt/bin:$PATH"' > /etc/profile.d/r2t-rt.sh
