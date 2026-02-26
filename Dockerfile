# ============================================================================
# NetSpectre - Deep Packet Inspection Engine
# Multi-stage Docker build for minimal image size
# ============================================================================

# --- Build Stage ---
FROM ubuntu:22.04 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    g++ make libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY include/ include/
COPY src/ src/
COPY Makefile.docker Makefile

RUN make all

# --- Runtime Stage ---
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy built binaries from builder
COPY --from=builder /app/build/ ./build/

# Copy sample test data generator
COPY generate_test_pcap.py .

# Expose dashboard port
EXPOSE 8080

# Default: run the dashboard with a sample PCAP
ENTRYPOINT ["./build/dpi_dashboard"]
CMD ["--pcap", "sample.pcap", "--port", "8080"]
