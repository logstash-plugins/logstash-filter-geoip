IMAGE_PREFIX=logstash/filter-geoip

default:
	@echo "Tasks:"
	@echo "- test: run spec tests (via Docker build)"
	@echo "- dev/build: build dev image"
	@echo "- dev/run: run dev container then prompt bash"

test:
	docker build -f Dockerfile.spec -t ${IMAGE_PREFIX}-spec ..

dev/build:
	docker build -f Dockerfile.dev -t ${IMAGE_PREFIX}-dev ..

dev/run:
	docker run --rm -ti \
	    -v $$(pwd)/logstash.conf:/opt/logstash.conf:ro \
	    -v $$(pwd)/..:/opt/logstash-filter-geoip:rw \
	    ${IMAGE_PREFIX}-dev \
	    bash
