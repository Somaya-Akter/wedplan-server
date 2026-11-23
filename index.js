import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { MongoClient } from "mongodb";

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

app.use(
  cors({
    origin: "http://localhost:3000",
    credentials: true,
  })
);

app.use(express.json());

const client = new MongoClient(process.env.MONGODB_URI);

let database;

async function connectDatabase() {
  try {
    await client.connect();

    database = client.db("wedplan");

    console.log("MongoDB connected successfully");
  } catch (error) {
    console.error("MongoDB connection failed:", error.message);
    process.exit(1);
  }
}

app.get("/", (req, res) => {
  res.send("WedPlan Server is running");
});

app.get("/health", (req, res) => {
  res.status(200).send({
    success: true,
    message: "WedPlan API is healthy",
  });
});

async function startServer() {
  await connectDatabase();

  app.listen(port, () => {
    console.log(`WedPlan server running on port ${port}`);
  });
}

startServer();