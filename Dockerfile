FROM golang:alpine
MAINTAINER Florian Fink <finkf@cis.lmu.de>
ENV DATE='Fr 24. Mai 20:29:35 CEST 2019'

# ENV PCWAUTH_GIT=github.com/finkf/pcwauth
# ENV GO111MODULE=on
# RUN apk add git &&\
# 	go get -u ${PCWAUTH_GIT} &&\
# 	apk del git
COPY pcwauth /go/bin/
CMD pcwauth \
	-dsn "${MYSQL_USER}:${MYSQL_PASSWORD}@(db)/${MYSQL_DATABASE}" \
	-pocoweb http://pocoweb:8080 \
	-profiler http://pcwprofiler \
	-users http://pcwusers \
    -postcorrection http://pcwpostcorrection \
	-listen ':80' \
	-debug
