FROM debian:bullseye

EXPOSE 500
EXPOSE 4500

RUN apt-get update -y && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y strongswan strongswan-pki libcharon-extra-plugins && \
    rm -rf /var/lib/apt/lists/*

COPY startup.sh /opt/

RUN chmod +x /opt/startup.sh

CMD ["/opt/startup.sh"]