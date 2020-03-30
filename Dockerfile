FROM alpine:latest AS build

RUN mkdir /crithit 

COPY crithit/ /crithit/crithit/
COPY dep/ /crithit/dep/

RUN rm /crithit/crithit/CMakeCache.txt
RUN cd /crithit/dep \
    && tar xjf /crithit/dep/boost_1_70_0.tar.bz2 

RUN ls -la /crithit/dep

RUN apk add --no-cache --virtual .build-deps \
        build-base \
        cmake \
        linux-headers \
        openssl-dev \
    && rm -rf /var/lib/apt/lists/* \ 
    && cd /crithit/crithit \
    && cmake -DBoost_INCLUDE_DIR=/crithit/dep/boost_1_70_0/ . \
    && make

FROM alpine:latest 

RUN apk add --no-cache \
    openssl-dev \
    libstdc++ \
    libgcc \
    ca-certificates

COPY --from=build /crithit/crithit/crithit /usr/sbin

ENTRYPOINT ["/usr/sbin/crithit"]

