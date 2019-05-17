SUDO ?= sudo
TAG ?= flobar/pcwauth
PORTS ?= 8080:80

default: docker-run

pcwauth: main.go
	go build .

.PHONY: docker-build
docker-build: Dockerfile pcwauth
	${SUDO} docker build -t ${TAG} .

.PHONY: docker-run
docker-run: docker-build
	${SUDO} docker run -p ${PORTS} -t ${TAG}

.PHONY: docker-push
docker-push: docker-build
	${SUDO} docker push ${TAG}

.PHONY: clean
clean:
	$(RM) pcwauth
