import dotenv from "dotenv";
import { betterAuth } from "better-auth";
import { mongodbAdapter } from "better-auth/adapters/mongodb";
import { MongoClient } from "mongodb";

dotenv.config();

const mongoClient = new MongoClient(process.env.MONGODB_URI);

const db = mongoClient.db("wedplan");

const clientUrl =
  process.env.CLIENT_URL ||
  "https://wedplan-client-cry2.vercel.app";

const serverUrl =
  process.env.BETTER_AUTH_URL ||
  "https://wedplan-server-4ua0.onrender.com";

export const auth = betterAuth({
  database: mongodbAdapter(db, {
    client: mongoClient,
  }),

  baseURL: serverUrl,

  basePath: "/api/auth",

  secret: process.env.BETTER_AUTH_SECRET,

  trustedOrigins: [
    "http://localhost:3000",
    "https://wedplan-client-cry2.vercel.app",
    clientUrl,
  ].filter(Boolean),

  emailAndPassword: {
    enabled: true,
    minPasswordLength: 6,
    autoSignIn: true,
  },

  socialProviders:
    process.env.GOOGLE_CLIENT_ID &&
    process.env.GOOGLE_CLIENT_SECRET
      ? {
          google: {
            clientId: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
          },
        }
      : {},

  user: {
    additionalFields: {
      role: {
        type: "string",
        required: false,
        defaultValue: "customer",
        input: true,
      },

      requestedRole: {
        type: "string",
        required: false,
        defaultValue: "customer",
        input: true,
      },

      isBlocked: {
        type: "boolean",
        required: false,
        defaultValue: false,
        input: false,
      },

      businessName: {
        type: "string",
        required: false,
        defaultValue: "",
        input: true,
      },

      subscriptionPlan: {
        type: "string",
        required: false,
        defaultValue: "Free",
        input: false,
      },

      subscriptionExpiresAt: {
        type: "date",
        required: false,
        input: false,
      },
    },
  },

  databaseHooks: {
    user: {
      create: {
        before: async (user) => {
          const requestedRole = String(
            user.requestedRole || user.role || "customer"
          ).toLowerCase();

          const safeRole =
            requestedRole === "vendor"
              ? "vendor"
              : "customer";

          return {
            data: {
              ...user,
              role: safeRole,
              requestedRole: safeRole,
              isBlocked: false,
              subscriptionPlan: "Free",
            },
          };
        },
      },
    },
  },

  advanced: {
    useSecureCookies:
      process.env.NODE_ENV === "production",

    defaultCookieAttributes: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite:
        process.env.NODE_ENV === "production"
          ? "none"
          : "lax",
    },
  },
});