# Snort in Docker

FROM ubuntu:14.04

MAINTAINER John Lin <linton.tw@gmail.com>

RUN apt-get update && \
    apt-get install -qy --no-install-recommends \
        python-setuptools \
        wget \
        build-essential \
        bison \
        flex \
        libpcap-dev \
        libpcre3-dev \
        libdumbnet-dev \
        zlib1g-dev \
        iptables-dev \
        libnetfilter-queue1 \
        vim \
        tmux \
        unzip

# Define working directory.
WORKDIR /opt

ENV DAQ_VERSION 2.0.5
RUN wget https://www.snort.org/downloads/snort/daq-${DAQ_VERSION}.tar.gz \
    && tar xvfz daq-${DAQ_VERSION}.tar.gz \
    && cd daq-${DAQ_VERSION} \
    && ./configure; make; make install

ENV SNORT_VERSION 2.9.7.3
RUN wget https://www.snort.org/downloads/snort/snort-${SNORT_VERSION}.tar.gz \
    && tar xvfz snort-${SNORT_VERSION}.tar.gz \
    && cd snort-${SNORT_VERSION} \
    && ./configure; make; make install

RUN ldconfig

# pigrelay
RUN wget --no-check-certificate \
        https://github.com/John-Lin/pigrelay/archive/master.zip \
    && unzip master.zip

ENV SNORT_RULES_SNAPSHOT 2972
ADD snortrules-snapshot-${SNORT_RULES_SNAPSHOT} /opt
RUN mkdir -p /var/log/snort && \
    mkdir -p /usr/local/lib/snort_dynamicrules && \
    mkdir -p /etc/snort && \
    # mkdir -p /etc/snort/rules && \
    # mkdir -p /etc/snort/preproc_rules && \
    # mkdir -p /etc/snort/so_rules && \
    # mkdir -p /etc/snort/etc && \
    cp -r /opt/rules /etc/snort/rules && \
    cp -r /opt/preproc_rules /etc/snort/preproc_rules && \
    cp -r /opt/so_rules /etc/snort/so_rules && \
    cp -r /opt/etc /etc/snort/etc && \
    # touch /etc/snort/rules/local.rules && \
    touch /etc/snort/rules/white_list.rules /etc/snort/rules/black_list.rules

# Clean up APT when done.
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* \
    /opt/snort-${SNORT_VERSION}.tar.gz /opt/daq-${DAQ_VERSION}.tar.gz


ENV NETWORK_INTERFACE eth0
# Validate an installation
# snort -T -i eth0 -c /etc/snort/etc/snort.conf
CMD ["snort", "-T", "-i", "echo ${NETWORK_INTERFACE}", "-c", "/etc/snort/etc/snort.conf"]
