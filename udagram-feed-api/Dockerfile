FROM node:13

# App directory
WORKDIR /app/

# Copy app source
COPY www/ ./

# Install dependencies
RUN npm install

EXPOSE 8080

# Start app
CMD [ "node", "server.js" ]