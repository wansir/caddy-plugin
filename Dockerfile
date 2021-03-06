# Copyright 2018 The KubeSphere Authors. All rights reserved.
# Use of this source code is governed by a Apache license
# that can be found in the LICENSE file.

FROM golang:1.10.2-alpine3.7 as build

RUN apk add --no-cache git

#RUN mkdir -p /go/src/kubesphere.io/caddy-plugin
RUN git clone https://github.com/kubesphere/caddy-plugin /go/src/kubesphere.io/caddy-plugin && \
 git clone --single-branch -b v0.11.0 -q https://github.com/mholt/caddy /go/src/github.com/mholt/caddy
RUN sed -i "/\/\/ This is where other plugins get plugged in (imported)/a\\\t_ \"kubesphere.io/caddy-plugin/auth\"\n\t_ \"kubesphere.io/caddy-plugin/addmission\"" /go/src/github.com/mholt/caddy/caddy/caddymain/run.go && \
 sed -i "/\/\/ github.com\/BTBurke\/caddy-jwt/a\\\t\"auth\",\n\t\"admission\"," /go/src/github.com/mholt/caddy/caddyhttp/httpserver/plugin.go

WORKDIR /go/src/github.com/mholt/caddy

RUN go install ./...

FROM alpine:3.7
COPY --from=build /go/bin/* /usr/local/bin/
COPY . /etc/caddy/
CMD ["sh"]



