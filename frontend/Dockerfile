FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --legacy-peer-deps
ARG NEXT_PUBLIC_API_URL=https://api.169-58-221-49.nip.io
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL
COPY . .
RUN npm run build
EXPOSE 3000
CMD ["npm", "start"]