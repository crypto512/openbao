# Copyright (c) OpenBao a Series of LF Projects, LLC
# SPDX-License-Identifier: MPL-2.0

# SWTPM Dockerfile with Manufacturer CA Integration
# This container provides a software TPM 2.0 with proper manufacturer EK certificates

FROM ubuntu:24.04

# Install base dependencies
RUN apt update && apt -y install  \
    acl \
    autoconf \
    autoconf-archive \
    automake \
    build-essential \
    curl \
    dbus \
    dbus-x11 \
    dh-autoreconf \
    doxygen \
    expect \
    gawk \
    gcc \
    git \
    gnutls-bin \
    iproute2 \
    jq \
    libcmocka-dev \
    libcmocka0 \
    libcurl4-openssl-dev \
    libfuse-dev \
    libglib2.0-dev \
    libgnutls28-dev \
    libini-config-dev \
    libjson-c-dev \
    libjson-glib-dev \
    libseccomp-dev \
    libssl-dev \
    libtasn1-6-dev \
    libtool \
    make \
    net-tools \
    netcat-openbsd \
    openssl \
    pandoc \
    pkg-config \
    procps \
    socat \
    sudo \
    uthash-dev \
    uuid-dev \
    xxd \
    && rm -rf /var/lib/apt/lists/*

# Install tpm2-tss (TPM2 Software Stack)
RUN git clone https://github.com/tpm2-software/tpm2-tss ~/tpm2-tss && \
    cd ~/tpm2-tss && \
    git checkout 4.1.3 && \
    ./bootstrap && \
    ./configure && \
    make -j$(nproc) && \
    make install && \
    ldconfig && \
    cd ~ && rm -rf ~/tpm2-tss

# Install tpm2-tools
RUN git clone https://github.com/tpm2-software/tpm2-tools ~/tpm2-tools && \
    cd ~/tpm2-tools && \
    git checkout 5.7 && \
    ./bootstrap && \
    ./configure && \
    make -j$(nproc) && \
    make install && \
    ldconfig && \
    cd ~ && rm -rf ~/tpm2-tools

# Install tpm2-abrmd (TPM2 Access Broker & Resource Manager)
RUN git clone https://github.com/tpm2-software/tpm2-abrmd ~/tpm2-abrmd && \
    cd ~/tpm2-abrmd && \
    git checkout 3.0.0 && \
    ./bootstrap && \
    ./configure && \
    make -j$(nproc) && \
    make install && \
    ldconfig && \
    cd ~ && rm -rf ~/tpm2-abrmd

# Install libtpms (TPM library implementation)
RUN git clone https://github.com/stefanberger/libtpms ~/libtpms && \
    cd ~/libtpms && \
    git checkout v0.10.0 && \
    ./autogen.sh --with-tpm2 --with-openssl && \
    make -j$(nproc) && \
    make install && \
    ldconfig && \
    cd ~ && rm -rf ~/libtpms

# Install swtpm (Software TPM Emulator)
RUN git clone https://github.com/stefanberger/swtpm ~/swtpm && \
    cd ~/swtpm && \
    git checkout v0.10.0 && \
    ./autogen.sh --with-openssl --prefix=/usr && \
    make -j$(nproc) && \
    make install && \
    ldconfig && \
    cd ~ && rm -rf ~/swtpm

WORKDIR /app

# Create directories for custom CA
RUN mkdir -p /etc/swtpm-ca /var/lib/swtpm-localca /root/.config

# Copy entrypoint script and CA configuration
COPY --chmod=770 entrypoint.sh /app/
COPY swtpm-localca.conf /root/.config/swtpm-localca.conf
COPY swtpm-localca.options /root/.config/swtpm-localca.options

# Expose TPM ports
# Port 2321: TPM command/response port
# Port 2322: TPM control port
EXPOSE 2321 2322

ENTRYPOINT ["/app/entrypoint.sh"]
