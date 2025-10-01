# ---------- Stage 1: Builder ----------
# This stage downloads and prepares our security tools (Trivy, Kubescape)
FROM ubuntu:24.04 AS builder

RUN apt-get update && apt-get install -y curl wget ca-certificates \
    && update-ca-certificates

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install Kubescape
RUN curl -L "https://github.com/kubescape/kubescape/releases/latest/download/kubescape-ubuntu-latest" \
    -o /usr/local/bin/kubescape \
    && chmod +x /usr/local/bin/kubescape

# ---------- Stage 2: Runtime ----------
# This is the final, minimal image that runs the Python application
FROM python:3.12-slim

WORKDIR /app

# --- SECURITY ENHANCEMENT: Create a non-root user ---
# Create a dedicated group and user for the application to run as
RUN addgroup --system --gid 1001 appgroup && \
    adduser --system --uid 1001 --ingroup appgroup appuser

# Copy app code and the tools from the builder stage
COPY . /app
COPY --from=builder /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=builder /usr/local/bin/kubescape /usr/local/bin/kubescape

# Install Python dependencies
# The '|| true' handles cases where requirements.txt might be empty or missing
RUN pip install --no-cache-dir -r requirements.txt || true \
    && chmod +x /app/setup.sh

# --- SECURITY ENHANCEMENT: Change file ownership ---
# Transfer ownership of the application directory to the new non-root user
RUN chown -R appuser:appgroup /app

# --- SECURITY ENHANCEMENT: Switch to the non-root user ---
# All subsequent commands will be run as 'appuser'
USER appuser

# Expose the default port (can be overridden by the entrypoint script)
EXPOSE 5000

# Use the setup script as the entrypoint
ENTRYPOINT ["/app/setup.sh"]
