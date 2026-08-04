FROM cal-diy-api:aip-f004349 AS built

FROM node:20-alpine

WORKDIR /calcom

RUN ln -s /usr/lib/libssl.so.3 /lib/libssl.so.3

ENV NODE_ENV=production
ENV NODE_OPTIONS=--max-old-space-size=8192
ENV USE_POOL=true

COPY --from=built /calcom /calcom

EXPOSE 80

CMD ["yarn", "workspace", "@calcom/api-v2", "start:prod"]
