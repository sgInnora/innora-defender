FROM ubuntu:20.04

RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-dev \
    binutils binwalk xxd hexdump \
    file strace ltrace \
    nmap tcpdump netcat \
    --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

RUN pip3 install yara-python pefile oletools volatility3

WORKDIR /analysis

CMD ["/bin/bash"]
