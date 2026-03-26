FROM python:3.11-slim

LABEL maintainer="bgp-ls-collector"
LABEL description="BGP-LS Topology Collector for Nokia SROS Routers"

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY bgp_ls_collector/ bgp_ls_collector/
COPY config.yaml .

# BGP requires port 179; API listens on 8080
EXPOSE 179 8080

# Allow non-root to bind port 179 via capability or port override
# In production use --bgp-port 1179 and NAT/iptables to 179,
# or run as root / with NET_BIND_SERVICE capability.

ENV BGPLS_LOG_LEVEL=INFO \
    BGPLS_LOG_FORMAT=text

ENTRYPOINT ["python", "-m", "bgp_ls_collector.main"]
CMD ["--config", "config.yaml"]
