ARG harbor_base_image_version
ARG harbor_base_namespace
FROM ${harbor_base_namespace}/harbor-registry-base:${harbor_base_image_version}

COPY ./harbor-build/install_cert.sh /home/harbor
COPY ./harbor-build/entrypoint.sh /home/harbor
COPY ./binary/registry /usr/bin/registry_DO_NOT_USE_GC

RUN chown -R harbor:harbor /etc/pki/tls/certs \
    && chown harbor:harbor /home/harbor/entrypoint.sh && chmod u+x /home/harbor/entrypoint.sh \
    && chown harbor:harbor /home/harbor/install_cert.sh && chmod u+x /home/harbor/install_cert.sh \
    && chown harbor:harbor /usr/bin/registry_DO_NOT_USE_GC && chmod u+x /usr/bin/registry_DO_NOT_USE_GC

HEALTHCHECK CMD curl --fail -s http://127.0.0.1:5000 || curl -k --fail -s https://127.0.0.1:5443 || exit 1

USER harbor

ENTRYPOINT ["/home/harbor/entrypoint.sh"]

VOLUME ["/storage"]
