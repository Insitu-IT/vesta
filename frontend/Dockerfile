ARG VNBUI_ARTIFACT_EDITION=community
# Build stage
FROM node:24.22.3-alpine AS builder
ARG VNBUI_ARTIFACT_EDITION
ENV VNBUI_ARTIFACT_EDITION=$VNBUI_ARTIFACT_EDITION

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN node --version && npm --version && npm ci

# Copy source
COPY . .

# Build application
RUN npm run build

# Production stage
FROM nginx:alpine
ARG VNBUI_ARTIFACT_EDITION
COPY LICENSE /usr/share/licenses/vnbui/LICENSE
COPY NOTICE /usr/share/licenses/vnbui/NOTICE
LABEL org.opencontainers.image.licenses="LicenseRef-Vesta-MMIT-1.1"

# Copy built dist
COPY --from=builder /app/dist /usr/share/nginx/html

# Validate the shipped filesystem, not only the Vite setting. Public assets can
# otherwise reintroduce maps even when compilation disables their generation.
RUN customer_maps="$(find /usr/share/nginx/html -type f -iname '*.map' -print -quit)" && test -z "$customer_maps"
RUN if [ "$VNBUI_ARTIFACT_EDITION" = community ]; then \
      customer_chunks="$(find /usr/share/nginx/html -type f \( -name 'organizations-*.js' \
        -o -name 'billing-*.js' -o -name 'branding-*.js' -o -name 'org-selector-*.js' \) -print -quit)" && \
        test -z "$customer_chunks" || exit 1; \
      grep -R -l -E '/api/v1/(organizations|billing/usage|branding)' /usr/share/nginx/html; \
      customer_scan_status=$?; test "$customer_scan_status" -eq 1; \
    fi

# Copy nginx configuration (full config, not just server block)
COPY nginx.conf /etc/nginx/nginx.conf

# OpenShift compatibility - avoid chowning /var/run (contains mounted K8s secrets)
RUN chown -R nginx:0 /usr/share/nginx/html /var/cache/nginx /var/log/nginx /etc/nginx/conf.d && \
    chmod -R g+rwX /usr/share/nginx/html /var/cache/nginx /var/log/nginx /etc/nginx/conf.d && \
    touch /var/run/nginx.pid && chown nginx:0 /var/run/nginx.pid && chmod g+rw /var/run/nginx.pid

EXPOSE 8080

USER nginx

CMD ["nginx", "-g", "daemon off;"]
