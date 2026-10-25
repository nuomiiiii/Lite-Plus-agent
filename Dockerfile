FROM alpine:3.21

WORKDIR /app

# Docker buildx 会在构建时自动填充这些变量
ARG TARGETOS
ARG TARGETARCH

COPY Lite-Plus-agent-${TARGETOS}-${TARGETARCH} /app/Lite-Plus-agent

RUN chmod +x /app/Lite-Plus-agent

# Plus marker is Lite-Plus-agent. Keep older markers so upgraded
# containers still skip binary self-update and layout relocate.
RUN touch /.lite-plus-agent-container /.lite-agent-container /.komari-agent-container

ENV GODEBUG=disablethp=1

ENTRYPOINT ["/app/Lite-Plus-agent"]
# 运行时请指定参数
# Please specify parameters at runtime.
# eg: docker run lite-plus-agent -e example.com -t token --enable-remote-control=false
CMD ["--help"]
