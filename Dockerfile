# Multi-stage build: compiles Volk and GNU Radio from source so that

# --------------------------------- #
# Base: runtime-only apt packages.
# --------------------------------- #
FROM ubuntu:22.04 AS base

ARG DEBIAN_FRONTEND=noninteractive
WORKDIR /tmp
USER root

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-numpy \
    python3-zmq \
    libzmq5 \
    libpython3.10 \
    libfftw3-3 \
    liblog4cpp5v5 \
    libspdlog1 \
    libboost-program-options1.74.0 \
    libboost-thread1.74.0 \
    libboost-chrono1.74.0 \
    libboost-filesystem1.74.0 \
    libboost-system1.74.0 \
    libboost-serialization1.74.0 && \
    rm -rf /var/lib/apt/lists/*

# --------------------------------- #
# Build: shared compile-time deps.
# --------------------------------- #
FROM base AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    cmake \
    build-essential \
    wget \
    ca-certificates \
    twine \
    python3-dev \
    python3-pip \
    python3-setuptools \
    python3-packaging \
    python3-requests \
    python3-mako \
    python3-numpy \
    python3-build \
    python3-venv \
    python3-yaml \
    pybind11-dev \
    libusb-1.0-0-dev \
    libsoapysdr-dev \
    libudev-dev \
    libzmq3-dev \
    libfftw3-dev \
    libspdlog-dev \
    liblog4cpp5-dev \
    libgmp-dev \
    libgsm1-dev \
    libthrift-dev \
    libcppunit-dev \
    libboost-program-options1.74-dev \
    libboost-thread1.74-dev \
    libboost-chrono1.74-dev \
    libboost-filesystem1.74-dev \
    libboost-system1.74-dev \
    libboost-serialization1.74-dev \
    libboost-date-time1.74-dev \
    libboost-regex1.74-dev \
    libboost-test1.74-dev && \
    wget -q -O /usr/include/zmq.hpp https://raw.githubusercontent.com/zeromq/cppzmq/v4.10.0/zmq.hpp && \
    wget -q -O /usr/include/zmq_addon.hpp https://raw.githubusercontent.com/zeromq/cppzmq/v4.10.0/zmq_addon.hpp && \
    python3 -m pip install --upgrade pip setuptools build twine numpy && \
    rm -rf /var/lib/apt/lists/*

# --------------------------------- #
# Volk: vector optimisation library.
# --------------------------------- #
FROM build AS volk

WORKDIR /tmp

RUN git clone --branch v3.1.0 --recursive --depth 1 --shallow-submodules \
        https://github.com/gnuradio/volk.git && \
    cd volk && mkdir build && cd build && \
    cmake -Wno-dev \
        -DCMAKE_INSTALL_PREFIX=/opt/volk \
        -DCMAKE_BUILD_TYPE=MinSizeRel \
        -DBUILD_TESTING=OFF \
        -DENABLE_TESTING=OFF \
        .. && \
    make -j"$(nproc)" && make install && \
    rm -rf /tmp/*

# --------------------------------- #
# Build GNU Radio from source
# --------------------------------- #
FROM build AS gnuradio

WORKDIR /tmp

COPY --from=volk /opt/volk/include /usr/include
COPY --from=volk /opt/volk/lib     /usr/lib
COPY --from=volk /opt/volk/bin     /usr/bin

RUN git clone --branch v3.10.12.0 --depth 1 \
        https://github.com/gnuradio/gnuradio.git && \
    cd gnuradio && mkdir build && cd build && \
    cmake -Wno-dev \
        -DCMAKE_INSTALL_PREFIX=/opt/gnuradio \
        -DGR_PYTHON_DIR=/opt/gnuradio/lib/python3.10/dist-packages \
        -DENABLE_GNURADIO_RUNTIME=ON \
        -DENABLE_PYTHON=ON \
        -DENABLE_GR_BLOCKS=ON \
        -DENABLE_GR_FILTER=ON \
        -DENABLE_GR_FFT=ON \
        -DENABLE_GR_ZEROMQ=ON \
        -DENABLE_GR_UHD=OFF \
        -DENABLE_GR_ANALOG=OFF \
        -DENABLE_GR_AUDIO=OFF \
        -DENABLE_GR_CHANNELS=OFF \
        -DENABLE_GR_CTRLPORT=OFF \
        -DENABLE_GR_DTV=OFF \
        -DENABLE_GR_FEC=OFF \
        -DENABLE_GR_NETWORK=OFF \
        -DENABLE_GR_PDU=OFF \
        -DENABLE_GR_QTGUI=OFF \
        -DENABLE_GR_SOAPY=OFF \
        -DENABLE_GR_TRELLIS=OFF \
        -DENABLE_GR_VIDEO_SDL=OFF \
        -DENABLE_GR_VOCODER=OFF \
        -DENABLE_GR_UTILS=OFF \
        -DENABLE_GR_MODTOOL=OFF \
        -DENABLE_GR_BLOCKTOOL=OFF \
        -DENABLE_MANPAGES=OFF \
        -DENABLE_TESTING=OFF \
        -DENABLE_DOXYGEN=OFF \
        -DENABLE_EXAMPLES=OFF \
        -DENABLE_GRC=OFF \
        .. && \
    make -j"$(nproc)" && make install && \
    rm -rf /tmp/*

# --------------------------------- #
# Runtime image.
# --------------------------------- #
FROM base AS runtime

WORKDIR /app

# Volk runtime
COPY --from=volk /opt/volk/lib /usr/lib
COPY --from=volk /opt/volk/bin /usr/bin

# GNU Radio runtime 
COPY --from=gnuradio /opt/gnuradio/lib   /usr/lib
COPY --from=gnuradio /opt/gnuradio/bin   /usr/bin
COPY --from=gnuradio /opt/gnuradio/share /usr/share

ENV PYTHONPATH=/usr/lib/python3.10/dist-packages

# TODO: This should be changed with your file
COPY geo_ntn_channel_emulator.py . 

# Exposes ports 2100 and 2102 from the container, may not be needed if using SDRs
EXPOSE 2100 2102 

# TODO: This should be changed with your file
ENTRYPOINT ["python3", "geo_ntn_channel_emulator.py", "--channel-delay-us=119720"]
