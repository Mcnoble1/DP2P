import express from "express";
import cors from "cors";
import morgan from "morgan";
import helmet from "helmet";
import dotenv from "dotenv";
import swaggerUi from "swagger-ui-express";
import swaggerSpec from "./config/swagger.js";

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());
app.use(morgan("dev"));
app.use(helmet());

app.use("/docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));

import routes from "./routes/index.js";

app.use("/api", routes);

app.get("/", (req, res) => {
  res.send("Welcome to the NGN↔USD P2P Platform API");
});

export default app;
