#!/bin/bash
set -e

function dev_plugin_build()
{
    cd ${WORKDIR}

    gem build $(find . -name *.gemspec)
}

function dev_plugin_install()
{
    echo "gem \"logstash-filter-geoip\", :path => \"${WORKDIR}\"" >> /opt/logstash/Gemfile

    plugin install --no-verify
}

function dev_logstash_run()
{
    logstash agent -w 1 -b 10 --debug -f /opt/logstash.conf
}

function dev_run()
{
    dev_plugin_install

    dev_logstash_run
}

export -f dev_plugin_install
export -f dev_plugin_build
export -f dev_logstash_run
export -f dev_run

exec "$@"