FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY gatekeeper ./gatekeeper

# Test stage: `docker build --target test .` fails the build if any test fails
FROM base AS test
COPY requirements-dev.txt .
RUN pip install --no-cache-dir -r requirements-dev.txt
COPY tests ./tests
RUN python -m pytest -q -p no:cacheprovider tests

FROM base AS final
RUN useradd --create-home --uid 1000 gatekeeper && mkdir -p /data && chown gatekeeper /data
USER gatekeeper
VOLUME /data
EXPOSE 8080
CMD ["python", "-m", "gatekeeper.main"]
