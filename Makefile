
default: docker

.PHONY: docker
docker:
	sudo docker build -t nginx_ja3 -f docker/debian-nginx-ssl-ja3/Dockerfile .

.PHONY: prod
prod:
	sudo docker build -t nginx-ja3-prod -f docker/debian-nginx-ssl-ja3/Dockerfile.deploy .
