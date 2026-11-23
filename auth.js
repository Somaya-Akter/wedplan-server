import dotenv from "dotenv";
import { MongoClient } from "mongodb";
import { betterAuth } from "better-auth";
import { mongodbAdapter } from "@better-auth/mongo-adapter";

dotenv.config();

const mongoClient = new MongoClient(process.env.MONGODB_URI);
const db = mongoClient.db("wedplan");

const googleEnabled =
  process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET;

export const auth = betterAuth({
  secret: process.env.BETTER_AUTH_SECRET,

  baseURL: process.env.BETTER_AUTH_URL || "http://localhost:5000",

  trustedOrigins: [
    process.env.CLIENT_URL || "http://localhost:3000",
  ],

  database: mongodbAdapter(db, {
    client: mongoClient,
  }),

  emailAndPassword: {
    enabled: true,
    minPasswordLength: 6,
    maxPasswordLength: 128,
  },

  socialProviders: googleEnabled
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
        type: ["customer", "vendor", "admin"],
        required: false,
        defaultValue: "customer",
        input: false,
      },

      requestedRole: {
        type: ["customer", "vendor"],
        required: false,
        input: true,
        returned: false,
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
        input: true,
      },

      subscriptionPlan: {
        type: ["Free", "Premium"],
        required: false,
        defaultValue: "Free",
        input: false,
      },

      subscriptionExpiresAt: {
        type: "string",
        required: false,
        input: false,
      },
    },
  },

  databaseHooks: {
    user: {
      create: {
        before: async (user) => {
          const selectedRole =
            user.requestedRole === "vendor" ? "vendor" : "customer";

          const { requestedRole, ...safeUser } = user;

          return {
            data: {
              ...safeUser,
              role: selectedRole,
              isBlocked: false,
              subscriptionPlan: "Free",
            },
          };
        },
      },
    },
  },

  advanced: {
    database: {
      joins: true,
    },
  },
});