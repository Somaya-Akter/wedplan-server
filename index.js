import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { MongoClient } from "mongodb";
import { toNodeHandler, fromNodeHeaders } from "better-auth/node";
import { auth } from "./auth.js";

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

app.use(
  cors({
    origin: process.env.CLIENT_URL || "http://localhost:3000",
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    credentials: true,
  })
);

// Better Auth route must come before express.json()
app.all("/api/auth/*splat", toNodeHandler(auth));

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

// Test current Better Auth session
app.get("/api/me", async (req, res) => {
  try {
    const session = await auth.api.getSession({
      headers: fromNodeHeaders(req.headers),
    });

    if (!session) {
      return res.status(401).send({
        success: false,
        message: "Unauthorized",
      });
    }

    return res.status(200).send({
      success: true,
      user: session.user,
      session: session.session,
    });
  } catch (error) {
    return res.status(500).send({
      success: false,
      message: error.message,
    });
  }
});

async function startServer() {
  await connectDatabase();

  app.listen(port, () => {
    console.log(`WedPlan server running on port ${port}`);
  });
}

startServer();