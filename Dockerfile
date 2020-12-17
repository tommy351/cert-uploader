FROM scratch
COPY cert-uploader /
ENTRYPOINT ["/cert-uploader"]
