FROM gcr.io/distroless/base
COPY cert-uploader /
ENTRYPOINT ["/cert-uploader"]
