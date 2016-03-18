# Develop with Docker

We provide 2 Docker images to help developer to run spec tests, and run logstash sample.

## Make tasks

From ./dev directory:

### Build

``make build`` to build the Docker image, from official jruby, with logstash 2.2 (see Dockerfile.dev)

### Test

``make test`` to run spec tests via a Docker build, from jruby 1.7 (see Dockerfile.spec)

### Run

``make run`` to run the Docker image just built ((see Dockerfile.dev) then prompt a bash shell.

Docker volumes:
- ./dev/logstash.conf ==> /opt/logstash.conf (read)
- . ==> /opt/logstash-filter-geoip (read-write)

## Inside the container

### Rake tasks

From Rakefile:

``rake vendor`` to download and build vendor

### Dev tasks

From dev/entrypoint.sh:

``dev_plugin_install`` to install the logstash plugin

``dev_run`` to install plugin then run logstash

``dev_logstash_run`` to run logstash (configuration from ./dev/logstash.conf)

``dev_plugin_build`` to build the gem

### Development livecycle

1. Install Docker (docker-machine can help)
2. Fork this repository and clone it on your machine
3. Open a shell to {PLUGIN_DIR}/dev
4. Build Docker image (``make dev/build``)
5. Run Docker container (``make dev/run``)
6. Install vendor if needed (inside container) (``rake vendor``)
7. Install plugin (inside container) (``dev_plugin_install``)
8. Work on plugin
9. Run logstash sample (inside container) (``dev_logstash_run``)
10. Run spec tests, from your machine (``make test``)


