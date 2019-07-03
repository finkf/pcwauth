SUDO ?= sudo
TAG ?= flobar/pcwauth
PORTS ?= 8080:80
TAGS := ${addprefix -t${TAG}:,${shell git describe --tags HEAD} latest}

default: docker-run

pcwauth: main.go
	CGO_ENABLED=0 go build .

.PHONY: docker-build
docker-build: Dockerfile pcwauth
	${SUDO} docker build ${TAGS} .

.PHONY: docker-run
docker-run: docker-build
	${SUDO} docker run -p ${PORTS} ${TAG}

.PHONY: docker-push
docker-push: docker-build
	${SUDO} docker push ${TAG}

.PHONY: clean
clean:
	$(RM) pcwauth
