FROM ubuntu:latest
MAINTAINER SOURENA
RUN rm /bin/sh && ln -s /bin/bash /bin/sh
RUN apt update && apt upgrade -y
RUN apt install git -y
RUN DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC apt-get -y install tzdata
RUN apt install python3 -y
RUN apt install python3-pip -y
RUN apt install python3.12-venv -y
RUN python3 -m venv venv
RUN source venv/bin/activate && python3 -m pip install jsoncomparison
RUN apt install libjansson-dev -y
RUN apt install lua5.4 -y
RUN apt install gcc -y
RUN apt install valgrind -y
RUN apt install liblua5.4-dev -y
RUN git clone https://github.com/maroofi/sdns.git
RUN cd sdns && make LUAINCDIR=/usr/include/lua5.4 all
RUN source venv/bin/activate && cd sdns/test && ./sdns_test.sh with-valgrind
RUN cd sdns && make LUAINCDIR=/usr/include/lua5.4 all
RUN echo "Done....."
