import { createServer } from "node:http";

const host = process.env.HOST ?? "127.0.0.1";
const port = Number(process.env.PORT ?? "8181");

const server = createServer((request, response) => {
  if (request.method === "GET" && request.url === "/") {
    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    response.end("<h1>Existing TypeScript application</h1>");
    return;
  }
  if (request.method === "GET" && request.url === "/identity") {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({
      user: request.headers["x-airlock-user-id"] ?? null,
      authorization: request.headers.authorization ?? null,
    }));
    return;
  }
  if (request.method === "POST" && request.url === "/sum") {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => { body += chunk; });
    request.on("end", () => {
      const values = JSON.parse(body) as { a: number; b: number };
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ total: values.a + values.b }));
    });
    return;
  }
  response.writeHead(404);
  response.end("not found");
});

server.listen(port, host);
