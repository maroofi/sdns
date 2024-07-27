FROM ubuntu:latest
MAINTAINER SOURENA
RUN rm /bin/sh && ln -s /bin/bash /bin/sh
RUN apt-get update && apt upgrade -y
RUN DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC apt-get -y install tzdata
RUN apt-get install git python3 python3-pip python3.12-venv  -y
RUN python3 -m venv venv
RUN source venv/bin/activate && python3 -m pip install jsoncomparison
RUN apt-get install gcc lua5.4 liblua5.4-dev libjansson-dev valgrind -y
RUN git clone https://github.com/maroofi/sdns.git
RUN cd sdns && make all
RUN source venv/bin/activate && cd sdns/test && ./sdns_test.sh with-valgrind
RUN cd sdns && make all
RUN cd sdns/bin && ldd libsdns.so
RUN echo "Done....."
