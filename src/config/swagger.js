import swaggerJSDoc from "swagger-jsdoc";

const options = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "DP2P API",
      version: "1.0.0",
      description: "API documentation for NGN↔USD P2P Platform",
    },
  },
  apis: ["./src/routes/*.js", "./src/models/*.js"],
};

export default swaggerJSDoc(options);
