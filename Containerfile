###############################################################################
# Rust builder stage - builds Rust plugins separately
###############################################################################
FROM registry.access.redhat.com/ubi10-minimal:10.0-1755721767 AS rust-builder

ARG PYTHON_VERSION=3.12

# Install Rust toolchain and Python development headers
# hadolint ignore=DL3041
RUN microdnf update -y && \
    microdnf install -y python${PYTHON_VERSION} python${PYTHON_VERSION}-devel gcc git curl && \
    microdnf clean all

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
ENV PATH="/root/.cargo/bin:$PATH"

WORKDIR /build

# Copy only Rust plugin files
COPY plugins_rust/ /build/plugins_rust/

# Switch to Rust plugin directory
WORKDIR /build/plugins_rust

# Build Rust plugins
RUN python${PYTHON_VERSION} -m venv /tmp/venv && \
    /tmp/venv/bin/pip install --upgrade pip maturin && \
    /tmp/venv/bin/maturin build --release --compatibility linux

###############################################################################
# Main application stage
###############################################################################
FROM registry.access.redhat.com/ubi10-minimal:10.0-1755721767
LABEL maintainer="Mihai Criveti" \
      name="mcp/mcpgateway" \
      version="0.8.0" \
      description="MCP Gateway: An enterprise-ready Model Context Protocol Gateway"

ARG PYTHON_VERSION=3.12

# Install Python and runtime dependencies (no build tools needed)
# hadolint ignore=DL3041
RUN microdnf update -y && \
    microdnf install -y python${PYTHON_VERSION} && \
    microdnf clean all

# Set default python3 to the specified version
RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python${PYTHON_VERSION} 1

WORKDIR /app

# Copy project files into container
COPY . /app

# Copy Rust plugin wheels from builder
COPY --from=rust-builder /build/plugins_rust/target/wheels/*.whl /tmp/rust-wheels/

# Create virtual environment, upgrade pip and install dependencies using uv for speed
# Including observability packages for OpenTelemetry support and Rust plugins
RUN python3 -m venv /app/.venv && \
    /app/.venv/bin/python3 -m pip install --upgrade pip setuptools pdm uv && \
    /app/.venv/bin/python3 -m uv pip install ".[redis,postgres,mysql,alembic,observability]" && \
    /app/.venv/bin/python3 -m pip install /tmp/rust-wheels/mcpgateway_rust-*-linux_x86_64.whl && \
    rm -rf /tmp/rust-wheels

# update the user permissions
RUN chown -R 1001:0 /app && \
    chmod -R g=u /app

# Expose the application port
EXPOSE 4444

# Set the runtime user
USER 1001

# Ensure virtual environment binaries are in PATH
ENV PATH="/app/.venv/bin:$PATH"

# Start the application using run-gunicorn.sh
CMD ["./run-gunicorn.sh"]
