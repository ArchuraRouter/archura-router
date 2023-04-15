FROM registry.access.redhat.com/ubi7/ubi-minimal

COPY target/archura-router /
EXPOSE 8080
ENTRYPOINT ["/archura-router"]