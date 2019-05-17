FROM golang:latest
MAINTAINER Florian Fink <finkf@cis.lmu.de>
ENV DATE='Fri 17 May 2019 12:22:42 PM CEST'

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
	-listen ':80' \
	-root-name ${PCW_ROOT_NAME} \
	-root-password ${PCW_ROOT_PASSWORD} \
	-root-email ${PCW_ROOT_EMAIL} \
	-root-institute ${PCW_ROOT_INSTITUTE} \
	-debug
