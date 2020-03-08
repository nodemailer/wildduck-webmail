# ---
from alpine:3.9 as builder

ARG UID=1000
ENV APP_PATH /app
WORKDIR ${APP_PATH}
COPY . .
RUN adduser -D -g '' builder -u ${UID}
RUN chown -R builder .

RUN apk add --no-cache nodejs
RUN apk add --no-cache openssl
RUN apk add --no-cache --virtual build-deps git python npm make g++

USER builder
RUN npm install && npm run bowerdeps

# ---
from alpine:3.9 as app
RUN apk add --no-cache nodejs
ENV APP_PATH /app
WORKDIR ${APP_PATH}
COPY --from=builder ${APP_PATH}/ ${APP_PATH}/
COPY --from=builder ${APP_PATH}/config/default.toml /etc/wildduck/www.toml
ENTRYPOINT ["node", "server.js"]
CMD ["--config=\"/etc/wildduck/www.toml\""]
