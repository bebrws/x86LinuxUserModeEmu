FROM debian:latest
WORKDIR /
RUN apt-get update; apt-get install build-essential gcc-multilib-i686-linux-gnu libc6-dev-i386
COPY . .
CMD ["flask", "run"]