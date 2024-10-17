FROM faust.cs.fau.de:5000/frontend_deps AS build

RUN cd /app; [ -d node_modules ] || npm install

FROM node:22-alpine

COPY ./app /app
COPY --from=build /app/node_modules /app/node_modules

#CMD ["npm","run","dev"]
WORKDIR /app
RUN npm run build
CMD ["npm", "run", "preview"]
