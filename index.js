import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import Stripe from "stripe";
import jwt from "jsonwebtoken";
import { MongoClient, ObjectId } from "mongodb";
import {
  toNodeHandler,
  fromNodeHeaders,
} from "better-auth/node";
import { auth } from "./auth.js";

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

const CLIENT_URL =
  process.env.CLIENT_URL || "http://localhost:3000";

const stripe = process.env.STRIPE_SECRET_KEY
  ? new Stripe(process.env.STRIPE_SECRET_KEY)
  : null;

const JWT_SECRET =
  process.env.JWT_SECRET ||
  process.env.BETTER_AUTH_SECRET ||
  "";

// =========================================================
// CORS
// =========================================================

app.use(
  cors({
    origin: CLIENT_URL,
    methods: [
      "GET",
      "POST",
      "PUT",
      "PATCH",
      "DELETE",
      "OPTIONS",
    ],
    credentials: true,
  })
);

// =========================================================
// DATABASE
// =========================================================

const client = new MongoClient(
  process.env.MONGODB_URI
);

let database;

const getUsersCollection = () =>
  database.collection("user");

const getServicesCollection = () =>
  database.collection("services");

const getBookingsCollection = () =>
  database.collection("bookings");

const getTransactionsCollection = () =>
  database.collection("transactions");

async function connectDatabase() {
  try {
    await client.connect();

    database = client.db("wedplan");

    console.log(
      "MongoDB connected successfully"
    );
  } catch (error) {
    console.error(
      "MongoDB connection failed:",
      error.message
    );

    process.exit(1);
  }
}

// =========================================================
// STRIPE WEBHOOK
// IMPORTANT: BEFORE express.json()
// =========================================================

app.post(
  "/api/stripe/webhook",
  express.raw({
    type: "application/json",
  }),
  async (req, res) => {
    if (!stripe) {
      return res.status(503).send({
        success: false,
        message:
          "Stripe is not configured.",
      });
    }

    if (!process.env.STRIPE_WEBHOOK_SECRET) {
      return res.status(503).send({
        success: false,
        message:
          "Stripe webhook secret is missing.",
      });
    }

    const signature =
      req.headers["stripe-signature"];

    let event;

    try {
      event =
        stripe.webhooks.constructEvent(
          req.body,
          signature,
          process.env
            .STRIPE_WEBHOOK_SECRET
        );
    } catch (error) {
      console.error(
        "Stripe webhook verification failed:",
        error.message
      );

      return res.status(400).send({
        success: false,
        message:
          "Invalid Stripe webhook signature.",
      });
    }

    try {
      if (
        event.type ===
          "checkout.session.completed" ||
        event.type ===
          "checkout.session.async_payment_succeeded"
      ) {
        const session =
          event.data.object;

        const vendorId =
          session.metadata?.vendorId;

        if (
          vendorId &&
          session.payment_status ===
            "paid"
        ) {
          const expiresAt = new Date();

          expiresAt.setDate(
            expiresAt.getDate() + 30
          );

          const vendorQuery =
            createUserIdQuery(vendorId);

          await getUsersCollection().updateOne(
            vendorQuery,
            {
              $set: {
                subscriptionPlan:
                  "Premium",

                subscriptionExpiresAt:
                  expiresAt,

                updatedAt: new Date(),
              },
            }
          );

          await getTransactionsCollection().updateOne(
            {
              stripeSessionId:
                session.id,
            },
            {
              $setOnInsert: {
                vendorId,

                plan: "Premium",

                amount:
                  (session.amount_total ||
                    0) / 100,

                currency: (
                  session.currency ||
                  "usd"
                ).toUpperCase(),

                stripeSessionId:
                  session.id,

                stripeSubscriptionId:
                  session.subscription ||
                  null,

                status: "succeeded",

                createdAt:
                  new Date(),
              },
            },
            {
              upsert: true,
            }
          );

          console.log(
            `Premium activated for vendor ${vendorId}`
          );
        }
      }

      return res.status(200).send({
        received: true,
      });
    } catch (error) {
      console.error(
        "Stripe webhook processing failed:",
        error
      );

      return res.status(500).send({
        success: false,
        message:
          "Stripe webhook processing failed.",
      });
    }
  }
);

// =========================================================
// BETTER AUTH
// IMPORTANT: BEFORE express.json()
// =========================================================

app.all(
  "/api/auth/*splat",
  toNodeHandler(auth)
);

// Body parser AFTER Better Auth + Stripe webhook
app.use(express.json());

// =========================================================
// HELPERS
// =========================================================

function escapeRegex(value = "") {
  return value.replace(
    /[.*+?^${}()|[\]\\]/g,
    "\\$&"
  );
}

function validObjectId(id) {
  return ObjectId.isValid(id);
}

function createUserIdQuery(userId) {
  if (ObjectId.isValid(userId)) {
    return {
      _id: new ObjectId(userId),
    };
  }

  return {
    id: userId,
  };
}

function formatDatabaseUser(user) {
  if (!user) return null;

  return {
    ...user,
    id:
      user.id ||
      user._id?.toString(),
  };
}

async function findUserById(userId) {
  const user =
    await getUsersCollection().findOne(
      createUserIdQuery(userId)
    );

  return formatDatabaseUser(user);
}

async function getSession(req) {
  return auth.api.getSession({
    headers: fromNodeHeaders(
      req.headers
    ),
  });
}

// =========================================================
// AUTH / JWT MIDDLEWARE
// =========================================================

async function requireAuth(
  req,
  res,
  next
) {
  try {
    // ---------------------------------
    // JWT Bearer authentication
    // ---------------------------------

    const authHeader =
      req.headers.authorization;

    if (
      authHeader?.startsWith("Bearer ")
    ) {
      if (!JWT_SECRET) {
        return res.status(500).send({
          success: false,
          message:
            "JWT secret is not configured.",
        });
      }

      const token =
        authHeader.split(" ")[1];

      try {
        const decoded = jwt.verify(
          token,
          JWT_SECRET
        );

        const databaseUser =
          await findUserById(
            decoded.sub
          );

        if (!databaseUser) {
          return res
            .status(401)
            .send({
              success: false,
              message:
                "JWT user not found.",
            });
        }

        if (
          databaseUser.isBlocked
        ) {
          return res
            .status(403)
            .send({
              success: false,
              message:
                "Your account has been blocked.",
            });
        }

        req.user = databaseUser;

        return next();
      } catch (error) {
        return res.status(401).send({
          success: false,
          message:
            "Invalid or expired JWT.",
        });
      }
    }

    // ---------------------------------
    // Better Auth session authentication
    // ---------------------------------

    const session =
      await getSession(req);

    if (!session?.user) {
      return res.status(401).send({
        success: false,
        message:
          "Unauthorized. Please sign in.",
      });
    }

    const databaseUser =
      await findUserById(
        session.user.id
      );

    const currentUser =
      databaseUser ||
      session.user;

    if (currentUser.isBlocked) {
      return res.status(403).send({
        success: false,
        message:
          "Your account has been blocked.",
      });
    }

    req.user = {
      ...session.user,
      ...currentUser,
      id: session.user.id,
    };

    req.session =
      session.session;

    next();
  } catch (error) {
    console.error(
      "Authentication error:",
      error.message
    );

    return res.status(401).send({
      success: false,
      message:
        "Invalid authentication session.",
    });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (
      !req.user ||
      !roles.includes(req.user.role)
    ) {
      return res.status(403).send({
        success: false,
        message:
          "Forbidden. You do not have permission.",
      });
    }

    next();
  };
}

// =========================================================
// BASIC ROUTES
// =========================================================

app.get("/", (req, res) => {
  res.send(
    "WedPlan Server is running"
  );
});

app.get(
  "/health",
  (req, res) => {
    res.status(200).send({
      success: true,
      message:
        "WedPlan API is healthy",
    });
  }
);

app.get(
  "/api/me",
  requireAuth,
  async (req, res) => {
    return res.send({
      success: true,
      user: req.user,
    });
  }
);

// =========================================================
// JWT TOKEN
// =========================================================

app.post(
  "/api/token",
  requireAuth,
  async (req, res) => {
    if (!JWT_SECRET) {
      return res.status(500).send({
        success: false,
        message:
          "JWT secret is not configured.",
      });
    }

    const token = jwt.sign(
      {
        role: req.user.role,
        email: req.user.email,
      },
      JWT_SECRET,
      {
        subject: req.user.id,
        expiresIn: "1h",
      }
    );

    return res.send({
      success: true,
      token,
    });
  }
);

// =========================================================
// PROFILE
// =========================================================

app.get(
  "/api/profile",
  requireAuth,
  async (req, res) => {
    const user =
      await findUserById(
        req.user.id
      );

    return res.send({
      success: true,
      user:
        user || req.user,
    });
  }
);

app.patch(
  "/api/profile",
  requireAuth,
  async (req, res) => {
    try {
      const {
        name,
        image,
        businessName,
      } = req.body;

      const updateData = {
        updatedAt: new Date(),
      };

      if (name !== undefined) {
        updateData.name =
          String(name).trim();
      }

      if (image !== undefined) {
        updateData.image =
          String(image).trim();
      }

      if (
        req.user.role ===
          "vendor" &&
        businessName !== undefined
      ) {
        updateData.businessName =
          String(
            businessName
          ).trim();
      }

      await getUsersCollection().updateOne(
        createUserIdQuery(
          req.user.id
        ),
        {
          $set: updateData,
        }
      );

      return res.send({
        success: true,
        message:
          "Profile updated successfully.",
      });
    } catch (error) {
      return res.status(500).send({
        success: false,
        message:
          "Failed to update profile.",
      });
    }
  }
);

// =========================================================
// PUBLIC SERVICES
// =========================================================

app.get(
  "/api/services",
  async (req, res) => {
    try {
      const {
        search = "",
        category = "",
        location = "",
        sort = "",
        limit = "",
      } = req.query;

      const query = {
        status: "Approved",
        isActive: true,
      };

      if (search.trim()) {
        query.serviceName = {
          $regex: escapeRegex(
            search.trim()
          ),
          $options: "i",
        };
      }

      if (category.trim()) {
        query.category = {
          $regex: `^${escapeRegex(
            category.trim()
          )}$`,
          $options: "i",
        };
      }

      if (location.trim()) {
        query.location = {
          $regex: escapeRegex(
            location.trim()
          ),
          $options: "i",
        };
      }

      let sortOption = {
        createdAt: -1,
      };

      if (sort === "price-asc") {
        sortOption = {
          price: 1,
        };
      }

      if (sort === "price-desc") {
        sortOption = {
          price: -1,
        };
      }

      let cursor =
        getServicesCollection()
          .find(query)
          .sort(sortOption);

      const parsedLimit =
        Number(limit);

      if (parsedLimit > 0) {
        cursor =
          cursor.limit(
            parsedLimit
          );
      }

      const services =
        await cursor.toArray();

      return res.send({
        success: true,
        count:
          services.length,
        services,
      });
    } catch (error) {
      return res.status(500).send({
        success: false,
        message:
          "Failed to load services.",
      });
    }
  }
);

// Featured services
app.get(
  "/api/services/featured/list",
  async (req, res) => {
    try {
      const services =
        await getServicesCollection()
          .find({
            status: "Approved",
            isActive: true,
          })
          .sort({
            createdAt: -1,
          })
          .limit(6)
          .toArray();

      return res.send({
        success: true,
        services,
      });
    } catch (error) {
      return res.status(500).send({
        success: false,
        message:
          "Failed to load featured services.",
      });
    }
  }
);

// Single service
app.get(
  "/api/services/:id",
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!validObjectId(id)) {
        return res
          .status(400)
          .send({
            success: false,
            message:
              "Invalid service ID.",
          });
      }

      const service =
        await getServicesCollection().findOne(
          {
            _id:
              new ObjectId(id),

            status: "Approved",

            isActive: true,
          }
        );

      if (!service) {
        return res
          .status(404)
          .send({
            success: false,
            message:
              "Service not found or unavailable.",
          });
      }

      return res.send({
        success: true,
        service,
      });
    } catch (error) {
      return res.status(500).send({
        success: false,
        message:
          "Failed to load service.",
      });
    }
  }
);

// =========================================================
// VENDOR OVERVIEW
// =========================================================

app.get(
  "/api/vendor/overview",
  requireAuth,
  requireRole("vendor"),
  async (req, res) => {
    try {
      const vendorId =
        req.user.id;

      const [
        totalServices,
        activeServices,
        pendingBookings,
        acceptedBookings,
      ] = await Promise.all([
        getServicesCollection().countDocuments(
          {
            vendorId,
          }
        ),

        getServicesCollection().countDocuments(
          {
            vendorId,
            status: "Approved",
            isActive: true,
          }
        ),

        getBookingsCollection().countDocuments(
          {
            vendorId,
            status: "Pending",
          }
        ),

        getBookingsCollection().countDocuments(
          {
            vendorId,
            status: "Accepted",
          }
        ),
      ]);

      return res.send({
        success: true,

        stats: {
          totalServices,
          activeServices,
          pendingBookings,
          acceptedBookings,

          subscriptionPlan:
            req.user
              .subscriptionPlan ||
            "Free",
        },
      });
    } catch (error) {
      return res.status(500).send({
        success: false,
        message:
          "Failed to load vendor overview.",
      });
    }
  }
);

// =========================================================
// VENDOR SERVICES
// =========================================================

app.get(
  "/api/vendor/services",
  requireAuth,
  requireRole("vendor"),
  async (req, res) => {
    try {
      const services =
        await getServicesCollection()
          .find({
            vendorId:
              req.user.id,
          })
          .sort({
            createdAt: -1,
          })
          .toArray();

      return res.send({
        success: true,
        services,
      });
    } catch (error) {
      return res.status(500).send({
        success: false,
        message:
          "Failed to load your services.",
      });
    }
  }
);

app.post(
  "/api/vendor/services",
  requireAuth,
  requireRole("vendor"),
  async (req, res) => {
    try {
      const {
        serviceName,
        category,
        description,
        price,
        location,
        images,
      } = req.body;

      if (
        !serviceName?.trim() ||
        !category?.trim() ||
        !description?.trim() ||
        !location?.trim() ||
        !price
      ) {
        return res
          .status(400)
          .send({
            success: false,
            message:
              "All required service fields must be provided.",
          });
      }

      const numericPrice =
        Number(price);

      if (
        !Number.isFinite(
          numericPrice
        ) ||
        numericPrice <= 0
      ) {
        return res
          .status(400)
          .send({
            success: false,
            message:
              "Price must be a valid positive number.",
          });
      }

      const serviceImages =
        Array.isArray(images)
          ? images.filter(Boolean)
          : images
            ? [images]
            : [];

      if (
        serviceImages.length ===
        0
      ) {
        return res
          .status(400)
          .send({
            success: false,
            message:
              "At least one service image is required.",
          });
      }

      const newService = {
        vendorId:
          req.user.id,

        vendorName:
          req.user.name || "",

        vendorEmail:
          req.user.email || "",

        vendorBusinessName:
          req.user
            .businessName || "",

        serviceName:
          serviceName.trim(),

        category:
          category.trim(),

        description:
          description.trim(),

        price:
          numericPrice,

        location:
          location.trim(),

        images:
          serviceImages,

        status: "Pending",

        isActive: true,

        createdAt:
          new Date(),

        updatedAt:
          new Date(),
      };

      const result =
        await getServicesCollection().insertOne(
          newService
        );

      return res.status(201).send({
        success: true,

        message:
          "Service submitted for admin approval.",

        service: {
          _id:
            result.insertedId,
          ...newService,
        },
      });
    } catch (error) {
      return res.status(500).send({
        success: false,

        message:
          "Failed to add service.",

        error:
          error.message,
      });
    }
  }
);

app.patch(
  "/api/vendor/services/:id",
  requireAuth,
  requireRole("vendor"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!validObjectId(id)) {
        return res
          .status(400)
          .send({
            success: false,
            message:
              "Invalid service ID.",
          });
      }

      const existingService =
        await getServicesCollection().findOne(
          {
            _id:
              new ObjectId(id),

            vendorId:
              req.user.id,
          }
        );

      if (!existingService) {
        return res
          .status(404)
          .send({
            success: false,
            message:
              "Service not found.",
          });
      }

      const allowedFields = [
        "serviceName",
        "category",
        "description",
        "price",
        "location",
        "images",
      ];

      const updateData = {};

      for (const field of allowedFields) {
        if (
          req.body[field] !==
          undefined
        ) {
          updateData[field] =
            req.body[field];
        }
      }

      if (
        updateData.price !==
        undefined
      ) {
        const numericPrice =
          Number(
            updateData.price
          );

        if (
          !Number.isFinite(
            numericPrice
          ) ||
          numericPrice <= 0
        ) {
          return res
            .status(400)
            .send({
              success: false,
              message:
                "Price must be valid.",
            });
        }

        updateData.price =
          numericPrice;
      }

      if (
        updateData.images &&
        !Array.isArray(
          updateData.images
        )
      ) {
        updateData.images = [
          updateData.images,
        ];
      }

      updateData.status =
        "Pending";

      updateData.updatedAt =
        new Date();

      await getServicesCollection().updateOne(
        {
          _id:
            new ObjectId(id),

          vendorId:
            req.user.id,
        },
        {
          $set: updateData,
        }
      );

      return res.send({
        success: true,
        message:
          "Service updated and sent for admin review.",
      });
    } catch (error) {
      return res.status(500).send({
        success: false,
        message:
          "Failed to update service.",
      });
    }
  }
);

app.patch(
  "/api/vendor/services/:id/availability",
  requireAuth,
  requireRole("vendor"),
  async (req, res) => {
    try {
      const { id } =
        req.params;

      const { isActive } =
        req.body;

      if (!validObjectId(id)) {
        return res
          .status(400)
          .send({
            success: false,
            message:
              "Invalid service ID.",
          });
      }

      if (
        typeof isActive !==
        "boolean"
      ) {
        return res
          .status(400)
          .send({
            success: false,
            message:
              "Invalid availability.",
          });
      }

      const service =
        await getServicesCollection().findOne(
          {
            _id:
              new ObjectId(id),

            vendorId:
              req.user.id,
          }
        );

      if (!service) {
        return res
          .status(404)
          .send({
            success: false,
            message:
              "Service not found.",
          });
      }

      if (
        isActive === true &&
        service.status ===
          "Approved" &&
        (req.user
          .subscriptionPlan ||
          "Free") !==
          "Premium"
      ) {
        const activeCount =
          await getServicesCollection().countDocuments(
            {
              vendorId:
                req.user.id,

              status:
                "Approved",

              isActive: true,

              _id: {
                $ne:
                  new ObjectId(
                    id
                  ),
              },
            }
          );

        if (activeCount >= 3) {
          return res
            .status(403)
            .send({
              success: false,

              message:
                "Free vendors can have a maximum of 3 active services. Upgrade to Premium.",
            });
        }
      }

      await getServicesCollection().updateOne(
        {
          _id:
            new ObjectId(id),

          vendorId:
            req.user.id,
        },
        {
          $set: {
            isActive,
            updatedAt:
              new Date(),
          },
        }
      );

      return res.send({
        success: true,

        message: isActive
          ? "Service activated successfully."
          : "Service deactivated successfully.",
      });
    } catch (error) {
      return res.status(500).send({
        success: false,
        message:
          "Failed to update availability.",
      });
    }
  }
);

app.delete(
  "/api/vendor/services/:id",
  requireAuth,
  requireRole("vendor"),
  async (req, res) => {
    try {
      const { id } =
        req.params;

      if (!validObjectId(id)) {
        return res
          .status(400)
          .send({
            success: false,
            message:
              "Invalid service ID.",
          });
      }

      const result =
        await getServicesCollection().deleteOne(
          {
            _id:
              new ObjectId(id),

            vendorId:
              req.user.id,
          }
        );

      if (!result.deletedCount) {
        return res
          .status(404)
          .send({
            success: false,
            message:
              "Service not found.",
          });
      }

      return res.send({
        success: true,
        message:
          "Service deleted successfully.",
      });
    } catch (error) {
      return res.status(500).send({
        success: false,
        message:
          "Failed to delete service.",
      });
    }
  }
);

// =========================================================
// CUSTOMER OVERVIEW
// =========================================================

app.get(
  "/api/customer/overview",
  requireAuth,
  requireRole("customer"),
  async (req, res) => {
    try {
      const customerId =
        req.user.id;

      const [
        total,
        pending,
        accepted,
        rejected,
      ] = await Promise.all([
        getBookingsCollection().countDocuments(
          {
            customerId,
          }
        ),

        getBookingsCollection().countDocuments(
          {
            customerId,
            status: "Pending",
          }
        ),

        getBookingsCollection().countDocuments(
          {
            customerId,
            status: "Accepted",
          }
        ),

        getBookingsCollection().countDocuments(
          {
            customerId,
            status: "Rejected",
          }
        ),
      ]);

      return res.send({
        success: true,

        stats: {
          total,
          pending,
          accepted,
          rejected,
        },
      });
    } catch (error) {
      return res.status(500).send({
        success: false,
        message:
          "Failed to load customer overview.",
      });
    }
  }
);

// =========================================================
// BOOKING SYSTEM
// =========================================================

app.post(
  "/api/bookings",
  requireAuth,
  requireRole("customer"),
  async (req, res) => {
    try {
      const {
        serviceId,
        eventDate,
        eventLocation,
        message = "",
      } = req.body;

      if (
        !serviceId ||
        !eventDate ||
        !eventLocation?.trim()
      ) {
        return res
          .status(400)
          .send({
            success: false,

            message:
              "Service, event date and event location are required.",
          });
      }

      if (
        !validObjectId(
          serviceId
        )
      ) {
        return res
          .status(400)
          .send({
            success: false,
            message:
              "Invalid service ID.",
          });
      }

      const service =
        await getServicesCollection().findOne(
          {
            _id:
              new ObjectId(
                serviceId
              ),

            status:
              "Approved",

            isActive: true,
          }
        );

      if (!service) {
        return res
          .status(404)
          .send({
            success: false,

            message:
              "Service not found or unavailable.",
          });
      }

      if (
        service.vendorId ===
        req.user.id
      ) {
        return res
          .status(403)
          .send({
            success: false,

            message:
              "You cannot book your own service.",
          });
      }

      const duplicate =
        await getBookingsCollection().findOne(
          {
            serviceId,

            customerId:
              req.user.id,

            eventDate,

            status: {
              $in: [
                "Pending",
                "Accepted",
              ],
            },
          }
        );

      if (duplicate) {
        return res
          .status(409)
          .send({
            success: false,

            message:
              "You already have an active booking for this service on this date.",
          });
      }

      const booking = {
        serviceId,

        serviceName:
          service.serviceName,

        serviceImage:
          service.images?.[0] ||
          "",

        vendorId:
          service.vendorId,

        vendorName:
          service
            .vendorBusinessName ||
          service.vendorName ||
          "",

        vendorEmail:
          service.vendorEmail ||
          "",

        customerId:
          req.user.id,

        customerName:
          req.user.name ||
          "",

        customerEmail:
          req.user.email ||
          "",

        eventDate,

        eventLocation:
          eventLocation.trim(),

        message:
          message.trim(),

        status: "Pending",

        createdAt:
          new Date(),

        updatedAt:
          new Date(),
      };

      const result =
        await getBookingsCollection().insertOne(
          booking
        );

      return res.status(201).send({
        success: true,

        message:
          "Booking request submitted successfully.",

        booking: {
          _id:
            result.insertedId,
          ...booking,
        },
      });
    } catch (error) {
      return res.status(500).send({
        success: false,

        message:
          "Failed to submit booking request.",

        error:
          error.message,
      });
    }
  }
);

app.get(
  "/api/customer/bookings",
  requireAuth,
  requireRole("customer"),
  async (req, res) => {
    try {
      const bookings =
        await getBookingsCollection()
          .find({
            customerId:
              req.user.id,
          })
          .sort({
            createdAt: -1,
          })
          .toArray();

      return res.send({
        success: true,
        bookings,
      });
    } catch (error) {
      return res.status(500).send({
        success: false,
        message:
          "Failed to load your bookings.",
      });
    }
  }
);

app.patch(
  "/api/customer/bookings/:id/cancel",
  requireAuth,
  requireRole("customer"),
  async (req, res) => {
    try {
      const { id } =
        req.params;

      if (!validObjectId(id)) {
        return res
          .status(400)
          .send({
            success: false,
            message:
              "Invalid booking ID.",
          });
      }

      const booking =
        await getBookingsCollection().findOne(
          {
            _id:
              new ObjectId(id),

            customerId:
              req.user.id,
          }
        );

      if (!booking) {
        return res
          .status(404)
          .send({
            success: false,
            message:
              "Booking not found.",
          });
      }

      if (
        booking.status !==
        "Pending"
      ) {
        return res
          .status(400)
          .send({
            success: false,

            message:
              "Only pending bookings can be cancelled.",
          });
      }

      await getBookingsCollection().updateOne(
        {
          _id:
            new ObjectId(id),

          customerId:
            req.user.id,

          status:
            "Pending",
        },
        {
          $set: {
            status:
              "Cancelled",

            updatedAt:
              new Date(),
          },
        }
      );

      return res.send({
        success: true,

        message:
          "Booking cancelled successfully.",
      });
    } catch (error) {
      return res.status(500).send({
        success: false,

        message:
          "Failed to cancel booking.",
      });
    }
  }
);

// =========================================================
// VENDOR BOOKING REQUESTS
// =========================================================

app.get(
  "/api/vendor/bookings",
  requireAuth,
  requireRole("vendor"),
  async (req, res) => {
    try {
      const bookings =
        await getBookingsCollection()
          .find({
            vendorId:
              req.user.id,
          })
          .sort({
            createdAt: -1,
          })
          .toArray();

      return res.send({
        success: true,
        bookings,
      });
    } catch (error) {
      return res.status(500).send({
        success: false,

        message:
          "Failed to load booking requests.",
      });
    }
  }
);

app.patch(
  "/api/vendor/bookings/:id/status",
  requireAuth,
  requireRole("vendor"),
  async (req, res) => {
    try {
      const { id } =
        req.params;

      const { status } =
        req.body;

      if (!validObjectId(id)) {
        return res
          .status(400)
          .send({
            success: false,
            message:
              "Invalid booking ID.",
          });
      }

      if (
        ![
          "Accepted",
          "Rejected",
        ].includes(status)
      ) {
        return res
          .status(400)
          .send({
            success: false,

            message:
              "Status must be Accepted or Rejected.",
          });
      }

      const booking =
        await getBookingsCollection().findOne(
          {
            _id:
              new ObjectId(id),

            vendorId:
              req.user.id,
          }
        );

      if (!booking) {
        return res
          .status(404)
          .send({
            success: false,

            message:
              "Booking request not found.",
          });
      }

      if (
        booking.status !==
        "Pending"
      ) {
        return res
          .status(400)
          .send({
            success: false,

            message:
              "This booking request has already been processed.",
          });
      }

      await getBookingsCollection().updateOne(
        {
          _id:
            new ObjectId(id),

          vendorId:
            req.user.id,

          status:
            "Pending",
        },
        {
          $set: {
            status,

            updatedAt:
              new Date(),
          },
        }
      );

      return res.send({
        success: true,

        message: `Booking ${status.toLowerCase()} successfully.`,
      });
    } catch (error) {
      return res.status(500).send({
        success: false,

        message:
          "Failed to update booking request.",
      });
    }
  }
);

// =========================================================
// ADMIN OVERVIEW
// =========================================================

app.get(
  "/api/admin/overview",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const [
        totalUsers,
        totalVendors,
        totalCustomers,
        totalServices,
        pendingServices,
        totalTransactions,
      ] = await Promise.all([
        getUsersCollection().countDocuments(
          {}
        ),

        getUsersCollection().countDocuments(
          {
            role: "vendor",
          }
        ),

        getUsersCollection().countDocuments(
          {
            role: "customer",
          }
        ),

        getServicesCollection().countDocuments(
          {}
        ),

        getServicesCollection().countDocuments(
          {
            status: "Pending",
          }
        ),

        getTransactionsCollection().countDocuments(
          {}
        ),
      ]);

      return res.send({
        success: true,

        stats: {
          totalUsers,
          totalVendors,
          totalCustomers,
          totalServices,
          pendingServices,
          totalTransactions,
        },
      });
    } catch (error) {
      return res.status(500).send({
        success: false,

        message:
          "Failed to load admin overview.",
      });
    }
  }
);

// =========================================================
// ADMIN USERS
// =========================================================

app.get(
  "/api/admin/users",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const {
        search = "",
        role = "",
      } = req.query;

      const query = {};

      if (search.trim()) {
        query.$or = [
          {
            name: {
              $regex:
                escapeRegex(
                  search.trim()
                ),

              $options: "i",
            },
          },

          {
            email: {
              $regex:
                escapeRegex(
                  search.trim()
                ),

              $options: "i",
            },
          },
        ];
      }

      if (
        ["customer", "vendor", "admin"].includes(
          role
        )
      ) {
        query.role = role;
      }

      const users =
        await getUsersCollection()
          .find(query)
          .sort({
            createdAt: -1,
          })
          .toArray();

      return res.send({
        success: true,

        users: users.map(
          (user) => ({
            ...user,

            id:
              user.id ||
              user._id.toString(),
          })
        ),
      });
    } catch (error) {
      return res.status(500).send({
        success: false,

        message:
          "Failed to load users.",
      });
    }
  }
);

app.patch(
  "/api/admin/users/:id/block",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const { id } =
        req.params;

      const { isBlocked } =
        req.body;

      if (
        typeof isBlocked !==
        "boolean"
      ) {
        return res
          .status(400)
          .send({
            success: false,

            message:
              "Invalid blocked status.",
          });
      }

      if (
        id === req.user.id &&
        isBlocked
      ) {
        return res
          .status(400)
          .send({
            success: false,

            message:
              "You cannot block your own admin account.",
          });
      }

      const result =
        await getUsersCollection().updateOne(
          createUserIdQuery(id),
          {
            $set: {
              isBlocked,

              updatedAt:
                new Date(),
            },
          }
        );

      if (!result.matchedCount) {
        return res
          .status(404)
          .send({
            success: false,
            message:
              "User not found.",
          });
      }

      return res.send({
        success: true,

        message: isBlocked
          ? "User blocked successfully."
          : "User unblocked successfully.",
      });
    } catch (error) {
      return res.status(500).send({
        success: false,

        message:
          "Failed to update user.",
      });
    }
  }
);

// =========================================================
// ADMIN SERVICES
// =========================================================

app.get(
  "/api/admin/services",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const {
        search = "",
        status = "",
      } = req.query;

      const query = {};

      if (search.trim()) {
        query.$or = [
          {
            serviceName: {
              $regex:
                escapeRegex(
                  search.trim()
                ),

              $options: "i",
            },
          },

          {
            vendorName: {
              $regex:
                escapeRegex(
                  search.trim()
                ),

              $options: "i",
            },
          },

          {
            vendorBusinessName: {
              $regex:
                escapeRegex(
                  search.trim()
                ),

              $options: "i",
            },
          },
        ];
      }

      if (status.trim()) {
        query.status =
          status.trim();
      }

      const services =
        await getServicesCollection()
          .find(query)
          .sort({
            createdAt: -1,
          })
          .toArray();

      return res.send({
        success: true,
        services,
      });
    } catch (error) {
      return res.status(500).send({
        success: false,
        message:
          "Failed to load services.",
      });
    }
  }
);

app.patch(
  "/api/admin/services/:id/review",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const { id } =
        req.params;

      const { status } =
        req.body;

      if (!validObjectId(id)) {
        return res
          .status(400)
          .send({
            success: false,
            message:
              "Invalid service ID.",
          });
      }

      if (
        ![
          "Approved",
          "Rejected",
        ].includes(status)
      ) {
        return res
          .status(400)
          .send({
            success: false,

            message:
              "Status must be Approved or Rejected.",
          });
      }

      const service =
        await getServicesCollection().findOne(
          {
            _id:
              new ObjectId(id),
          }
        );

      if (!service) {
        return res
          .status(404)
          .send({
            success: false,

            message:
              "Service not found.",
          });
      }

      if (
        status ===
          "Approved" &&
        service.isActive !== false
      ) {
        const vendor =
          await findUserById(
            service.vendorId
          );

        const plan =
          vendor?.subscriptionPlan ||
          "Free";

        if (plan !== "Premium") {
          const activeCount =
            await getServicesCollection().countDocuments(
              {
                vendorId:
                  service.vendorId,

                status:
                  "Approved",

                isActive: true,

                _id: {
                  $ne:
                    new ObjectId(
                      id
                    ),
                },
              }
            );

          if (
            activeCount >= 3
          ) {
            return res
              .status(403)
              .send({
                success:
                  false,

                message:
                  "This free vendor already has 3 active services. Premium upgrade is required.",
              });
          }
        }
      }

      await getServicesCollection().updateOne(
        {
          _id:
            new ObjectId(id),
        },
        {
          $set: {
            status,

            reviewedAt:
              new Date(),

            updatedAt:
              new Date(),
          },
        }
      );

      return res.send({
        success: true,

        message: `Service ${status.toLowerCase()} successfully.`,
      });
    } catch (error) {
      return res.status(500).send({
        success: false,

        message:
          "Failed to review service.",

        error:
          error.message,
      });
    }
  }
);

app.patch(
  "/api/admin/services/:id/status",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const { id } =
        req.params;

      const { isActive } =
        req.body;

      if (!validObjectId(id)) {
        return res
          .status(400)
          .send({
            success: false,

            message:
              "Invalid service ID.",
          });
      }

      if (
        typeof isActive !==
        "boolean"
      ) {
        return res
          .status(400)
          .send({
            success: false,

            message:
              "Invalid active status.",
          });
      }

      const result =
        await getServicesCollection().updateOne(
          {
            _id:
              new ObjectId(id),
          },
          {
            $set: {
              isActive,

              updatedAt:
                new Date(),
            },
          }
        );

      if (!result.matchedCount) {
        return res
          .status(404)
          .send({
            success: false,

            message:
              "Service not found.",
          });
      }

      return res.send({
        success: true,

        message:
          "Service status updated.",
      });
    } catch (error) {
      return res.status(500).send({
        success: false,

        message:
          "Failed to update service.",
      });
    }
  }
);

app.delete(
  "/api/admin/services/:id",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const { id } =
        req.params;

      if (!validObjectId(id)) {
        return res
          .status(400)
          .send({
            success: false,

            message:
              "Invalid service ID.",
          });
      }

      const result =
        await getServicesCollection().deleteOne(
          {
            _id:
              new ObjectId(id),
          }
        );

      if (!result.deletedCount) {
        return res
          .status(404)
          .send({
            success: false,

            message:
              "Service not found.",
          });
      }

      return res.send({
        success: true,

        message:
          "Service deleted successfully.",
      });
    } catch (error) {
      return res.status(500).send({
        success: false,

        message:
          "Failed to delete service.",
      });
    }
  }
);

// =========================================================
// STRIPE PREMIUM SUBSCRIPTION
// =========================================================

app.post(
  "/api/stripe/create-checkout-session",
  requireAuth,
  requireRole("vendor"),
  async (req, res) => {
    try {
      if (!stripe) {
        return res
          .status(503)
          .send({
            success: false,

            message:
              "Stripe is not configured yet.",
          });
      }

      const checkoutSession =
        await stripe.checkout.sessions.create(
          {
            mode:
              "subscription",

            customer_email:
              req.user.email,

            line_items: [
              {
                price_data: {
                  currency:
                    "usd",

                  unit_amount:
                    999,

                  recurring: {
                    interval:
                      "month",
                  },

                  product_data: {
                    name:
                      "WedPlan Premium Vendor Plan",

                    description:
                      "Unlimited active wedding services and Premium vendor benefits.",
                  },
                },

                quantity: 1,
              },
            ],

            metadata: {
              vendorId:
                req.user.id,

              plan:
                "Premium",
            },

            subscription_data: {
              metadata: {
                vendorId:
                  req.user.id,

                plan:
                  "Premium",
              },
            },

            success_url: `${CLIENT_URL}/payment/success?session_id={CHECKOUT_SESSION_ID}`,

            cancel_url: `${CLIENT_URL}/payment/cancel`,
          }
        );

      return res.send({
        success: true,

        url:
          checkoutSession.url,
      });
    } catch (error) {
      console.error(
        "Stripe checkout error:",
        error
      );

      return res.status(500).send({
        success: false,

        message:
          "Failed to create Stripe checkout session.",

        error:
          error.message,
      });
    }
  }
);

app.get(
  "/api/vendor/subscription",
  requireAuth,
  requireRole("vendor"),
  async (req, res) => {
    try {
      const user =
        await findUserById(
          req.user.id
        );

      return res.send({
        success: true,

        subscription: {
          plan:
            user?.subscriptionPlan ||
            "Free",

          expiresAt:
            user?.subscriptionExpiresAt ||
            null,
        },
      });
    } catch (error) {
      return res.status(500).send({
        success: false,

        message:
          "Failed to load subscription.",
      });
    }
  }
);

// =========================================================
// ADMIN TRANSACTIONS
// =========================================================

app.get(
  "/api/admin/transactions",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const transactions =
        await getTransactionsCollection()
          .find({})
          .sort({
            createdAt: -1,
          })
          .toArray();

      return res.send({
        success: true,
        transactions,
      });
    } catch (error) {
      return res.status(500).send({
        success: false,

        message:
          "Failed to load transactions.",
      });
    }
  }
);

// =========================================================
// API 404
// =========================================================

app.use(
  "/api/*splat",
  (req, res) => {
    return res.status(404).send({
      success: false,
      message:
        "API route not found.",
    });
  }
);

// =========================================================
// START SERVER
// =========================================================

async function startServer() {
  await connectDatabase();

  app.listen(port, () => {
    console.log(
      `WedPlan server running on port ${port}`
    );

    if (!stripe) {
      console.log(
        "Stripe key not configured yet"
      );
    }
  });
}

startServer();