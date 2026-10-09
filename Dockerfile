FROM node:22-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY server.js ./
COPY public ./public
COPY database ./database
EXPOSE 3000
USER node
CMD ["npm","start"]
