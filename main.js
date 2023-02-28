import createServer from "./server.js";

const server = createServer();

const port = process.env.PORT || 8080;

server.listen(port, () => {
  console.log("Server is listening at localhost:8080");
});
