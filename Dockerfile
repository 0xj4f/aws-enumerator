# syntax=docker/dockerfile:1
#
# aws-enumerator container image (F-132, F-160).
#
# * Base image pinned by digest: python:3.13-slim, OCI image index digest looked up on Docker Hub on
#   2026-10-15. Bump it deliberately (tag + digest + date) when updating.
# * BuildKit frontend: the "# syntax=docker/dockerfile:1" line above (needed for the RUN --mount bind in the
#   runtime stage) is a floating major tag that BuildKit resolves when it builds. It is not pinned yet: the digest
#   has to be looked up online. Pin it (docker/dockerfile:1@sha256:<digest>) and bump it deliberately, as the base
#   image is.
# * Multi-stage: the build stage downloads the hash-locked dependencies (requirements.txt, generated with
#   pip-compile --generate-hashes) and builds the project wheel with the hash-locked build backend
#   (requirements-build.txt); the runtime stage installs those wheels only and keeps no build tooling.
# * Runs as the unprivileged user app (uid/gid 10001). No AWS_* credential variables and no ~/.aws volume are
#   baked in: pass credentials at run time, for example a read-only profile mount (the README "Docker" recipe)
#     docker run --rm --user "$(id -u):$(id -g)" -e HOME=/aws-home \
#       -v "$HOME/.aws:/aws-home/.aws:ro" -e AWS_PROFILE=<profile> \
#       -v "$PWD/out:/reports" <image> collect --region <region>
#   --user lets the container read your 0600 credential files and write out/ as you. Docker sets HOME=/ for a uid
#   with no passwd entry, so HOME=/aws-home tells the SDK where .aws is; the mount point is neutral because
#   /home/app may be 0700 and owned by uid 10001, which another uid cannot enter. Or pass short-lived credentials
#   in a 0600 --env-file. Reports go to /reports (AWS_ENUMERATOR_OUTPUT), mode 0700.
# * The dashboard binds 127.0.0.1 by default; inside a container publish it on the host's loopback only:
#     docker run --rm -p 127.0.0.1:8000:8000 <image> dashboard --host 0.0.0.0 --no-browser

ARG PYTHON_IMAGE=python:3.13-slim@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f

FROM ${PYTHON_IMAGE} AS build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /src
COPY requirements.txt requirements-build.txt ./
RUN pip install --require-hashes --no-deps -r requirements-build.txt \
 && pip wheel --require-hashes --wheel-dir /wheels -r requirements.txt
COPY pyproject.toml readme.md LICENSE ./
COPY aws_enumerator ./aws_enumerator
RUN pip wheel --no-deps --no-build-isolation --wheel-dir /wheels .

FROM ${PYTHON_IMAGE} AS runtime
ARG VERSION=0.3.0
ARG GIT_SHA=unknown
LABEL org.opencontainers.image.title="aws-enumerator" \
      org.opencontainers.image.description="Enumerate an AWS account, analyse attack paths, visualise them locally. Authorized use only." \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${GIT_SHA}" \
      org.opencontainers.image.source="https://github.com/0xj4f/aws-enumerator" \
      org.opencontainers.image.licenses="MIT"
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    AWS_ENUMERATOR_OUTPUT=/reports \
    AWS_ENUMERATOR_GIT_SHA=${GIT_SHA}
RUN groupadd --gid 10001 app \
 && useradd --uid 10001 --gid 10001 --create-home --home-dir /home/app --shell /usr/sbin/nologin app \
 && install -d -m 0700 -o 10001 -g 10001 /reports
RUN --mount=type=bind,from=build,source=/wheels,target=/wheels \
    pip install --no-index --find-links=/wheels /wheels/*.whl
USER 10001:10001
WORKDIR /home/app
VOLUME ["/reports"]
EXPOSE 8000
ENTRYPOINT ["aws-enumerator"]
CMD ["--help"]
