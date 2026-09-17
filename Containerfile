# AI-Author: Codex (OpenAI model not exposed by runtime)
FROM registry.access.redhat.com/ubi9/nodejs-22@sha256:1ae32dfecc3221f1ebf2fa3e5518d80f47ca46da0f229b51957b9b02052ad85a AS node-runtime
FROM registry.access.redhat.com/ubi9/python-312:9.6
COPY --from=node-runtime /usr/bin/node /usr/bin/node
COPY --from=node-runtime /usr/lib64/libnode.so.127 /usr/lib64/libnode.so.127
COPY --from=node-runtime /usr/lib64/libcrypto.so.3 /opt/node-libs/libcrypto.so.3
COPY --from=node-runtime /usr/lib64/libssl.so.3 /opt/node-libs/libssl.so.3
RUN LD_LIBRARY_PATH=/opt/node-libs node --version
WORKDIR /opt/app-root/src
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY guardrail ./guardrail
COPY policies ./policies
COPY topology/render.mjs topology/specification.mjs ./topology/
COPY topology/vendor ./topology/vendor/
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
USER 1001
EXPOSE 8443
CMD ["python", "-m", "guardrail", "serve"]
