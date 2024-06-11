FROM mcr.microsoft.com/devcontainers/base:ubuntu

ARG THRIFT_VER='0.16.0'
# THRIFT PREQ
RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    apt-get -y install \
    automake \
    bison \
    flex \
    git \
    libboost-all-dev \
    libevent-dev \
    libssl-dev \
    libtool \
    make \ 
    pkg-config \
    g++ \
    gcc \
    tree \
    wget

# Thrift install steps were extracted from github repository build.yml file
RUN wget https://github.com/apache/thrift/archive/refs/tags/v${THRIFT_VER}.tar.gz -cO /tmp/thrift.tgz \
    && tar -C /tmp -xf /tmp/thrift.tgz  \
    && rm /tmp/thrift.tgz
WORKDIR /tmp/thrift-${THRIFT_VER}

RUN ./bootstrap.sh \
    && ./configure --disable-debug --disable-tests --disable-libs \
    && make -j$(nproc) \ 
    && make install \
    && rm -rf /tmp/thrift-${THRIFT_VERSION} \ 
    && apt-get remove -y gcc g++

# OSquery install 
ENV OSQUERY_KEY=1484120AC4E9F8A1A577AEEE97A80C63C9D8B80B
RUN apt-get -y update \
    && apt-get install -y software-properties-common \
    && apt-key adv --keyserver keyserver.ubuntu.com --recv-keys $OSQUERY_KEY \ 
    && add-apt-repository 'deb [arch=amd64] https://pkg.osquery.io/deb deb main' \ 
    && apt-get -y install osquery

# # GOLANG INSTAILL 
WORKDIR / 
ARG GO_VER='1.22.4'
RUN wget https://go.dev/dl/go${GO_VER}.linux-amd64.tar.gz \
    && tar -C /usr/local -xvf go${GO_VER}.linux-amd64.tar.gz \ 
    && rm go${GO_VER}.linux-amd64.tar.gz
ENV PATH=$PATH:/usr/local/go/bin


