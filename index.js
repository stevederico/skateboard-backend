// @deno-types="npm:@types/express"
import express from "npm:express";
import { MongoClient, ObjectId } from "npm:mongodb";
import Stripe from "npm:stripe";

import { create, verify } from "https://deno.land/x/djwt/mod.ts";
import * as bcrypt from "https://deno.land/x/bcrypt/mod.ts";
import { load } from "https://deno.land/std@0.195.0/dotenv/mod.ts";

await load({ export: true });

// Initialize MongoDB connection
const client = new MongoClient(Deno.env.get("MONGODB_URI") || "mongodb://localhost:27017");
await client.connect();
const db = client.db("SkateboardApp");
const users = db.collection("Users");

// Ensure indexes for performance
await users.createIndex({ email: 1 }, { unique: true });

// Stripe initialization
const stripe = new Stripe(Deno.env.get("STRIPE_KEY"));

// JWT helper: Generates a token for a given userId
async function generateToken(userId) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(Deno.env.get("JWT_SECRET")),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
  return create({ alg: "HS256", typ: "JWT" }, { userId }, key);
}

// Create Express app
const app = express();

app.use(
  express.json({
    verify: (req, res, buf) => {
      req.rawBody = buf; // Store the raw buffer
    }
  })
);

// Simple CORS middleware
app.use((req, res, next) => {
  res.set({
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  });
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// Middleware to parse JSON and URL-encoded data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files from the 'public' directory
app.use(express.static("public"));

// POST /signup - Create a new user
app.post("/signup", async (req, res) => {
  try {
    const { email, password, name } = req.body;
    const trimmedEmail = email?.trim();
    const trimmedName = name?.trim();

    if (!trimmedEmail || !password?.trim() || !trimmedName) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(trimmedEmail)) {
      return res.status(400).json({ error: "Invalid email format" });
    }

    const existingUser = await users.findOne({ email: trimmedEmail });
    if (existingUser) {
      return res.status(409).json({ error: "Email already exists" });
    }

    const salt = await bcrypt.genSalt(12);
    const hash = await bcrypt.hash(password, salt);

    const result = await users.insertOne({
      email: trimmedEmail,
      password: hash,
      name: trimmedName,
      stripeID: null,
      expires: null,
      subStatus: null
    });
    
    const newUser = await users.findOne({ _id: result.insertedId });
    const token = await generateToken(newUser._id.toString());
    
    res.status(201).json({
      id: newUser._id.toString(),
      email: newUser.email,
      name: newUser.name,
      token
    });
  } catch (error) {
    res.status(500).json({ error: "Internal server error", details: error.message });
  }
});

// POST /signin - Authenticate user
app.post("/signin", async (req, res) => {
  try {
    if (!req.headers["content-type"]?.includes("application/json")) {
      throw new Error("Content-Type must be application/json");
    }
    const { email, password } = req.body;
    if (!email || !password) throw new Error("Email and password are required");

    const user = await users.findOne({ email: email.trim() });
    if (user && (await bcrypt.compare(password, user.password))) {
      const token = await generateToken(user._id.toString());
      const responseObj = {
        id: user._id.toString(),
        email: user.email,
        name: user.name,
        stripeID: user.stripeID,
        expires: user.expires,
        subStatus: user.subStatus,
        token: token
      };
      return res.json(responseObj);
    }
    res.status(401).json({ error: "Invalid credentials" });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get("/me", async (req, res) => {
  try {
    // Get and validate authorization header
    const authHeader = req.headers["authorization"];
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Unauthorized: No valid token provided" });
    }

    const token = authHeader.split(" ")[1];
    if (!token) {
      return res.status(401).json({ error: "Unauthorized: Token missing" });
    }

    // Verify token using the same key as in generateToken
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(Deno.env.get("JWT_SECRET")),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign", "verify"]
    );

    // Verify and decode the token
    const payload = await verify(token, key);
    const userId = payload.userId;

    if (!userId) {
      return res.status(401).json({ error: "Unauthorized: Invalid token payload" });
    }

    // Fetch user from database
    const user = await users.findOne({ _id: new ObjectId(userId) });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Return user details (excluding password)
    res.json({
      id: user._id.toString(),
      email: user.email,
      name: user.name,
      stripeID: user.stripeID,
      expires: user.expires,
      subStatus: user.subStatus
    });
  } catch (error) {
    console.error("Error in /me endpoint:", error.message);
    if (error.name === "JWTError") {
      return res.status(401).json({ error: "Unauthorized: Invalid token" });
    }
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /isSubscriber - Check if the user is a subscriber
app.get("/isSubscriber", async (req, res) => {
  try {
    // Get and validate authorization header
    const authHeader = req.headers["authorization"];
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Unauthorized: No valid token provided" });
    }

    const token = authHeader.split(" ")[1];
    if (!token) {
      return res.status(401).json({ error: "Unauthorized: Token missing" });
    }

    // Verify token
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(Deno.env.get("JWT_SECRET")),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign", "verify"]
    );

    // Verify and decode the token
    const payload = await verify(token, key);
    const userId = payload.userId;

    if (!userId) {
      return res.status(401).json({ error: "Unauthorized: Invalid token payload" });
    }

    // Fetch user subscription status from database
    const user = await users.findOne(
      { _id: new ObjectId(userId) },
      { projection: { stripeID: 1, expires: 1, subStatus: 1 } }
    );

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Check if user has an active subscription
    const isSubscriber = user.stripeID && 
                         user.subStatus === "active" && 
                         (!user.expires || user.expires > Math.floor(Date.now() / 1000));

    res.json({ 
      isSubscriber,
      subscriptionDetails: {
        status: user.subStatus,
        expiresAt: user.expires ? new Date(user.expires * 1000).toISOString() : null
      }
    });
  } catch (error) {
    console.error("Error in /isSubscriber endpoint:", error.message);
    if (error.name === "JWTError") {
      return res.status(401).json({ error: "Unauthorized: Invalid token" });
    }
    res.status(500).json({ error: "Internal server error" });
  }
});

// POST /create-checkout-session - Create a Stripe checkout session
app.post("/create-checkout-session", async (req, res) => {
  try {
    const prices = await stripe.prices.list({
      lookup_keys: [req.body.lookup_key],
      expand: ["data.product"],
    });

    // Get the origin from the request headers
    const origin = req.get("origin");
    if (!origin) {
      return res.status(400).json({ error: "Missing Origin header" });
    }

    const session = await stripe.checkout.sessions.create({
      customer_email: req.body.email,
      mode: "subscription",
      payment_method_types: ['card'],
      line_items: [
        {
          price: prices.data[0].id,
          quantity: 1,
        },
      ],
      billing_address_collection: 'auto', // or 'required'
      success_url: `${origin}/app/stripe?success=true`,
      cancel_url: `${origin}/app/stripe?canceled=true`,
      subscription_data: {
        metadata: {
          email: req.body.email,
        },
      },
    });

    res.status(200).json({ url: session.url, id: session.id, customerID: session.customer });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Stripe session creation failed" });
  }
});

// POST /create-portal-session - Create a Stripe billing portal session
app.post("/create-portal-session", async (req, res) => {

  // Get the origin from the request headers
  const origin = req.get("origin");
  if (!origin) {
    return res.status(400).json({ error: "Missing Origin header" });
  }

  try {
    const { customerID } = req.body;
    const portalSession = await stripe.billingPortal.sessions.create({
      customer: customerID,
      return_url: `${origin}/app/stripe?portal=return`,
    });
    console.log("/create-portal-session ", portalSession.url);
    res.status(200).json({ url: portalSession.url, id: portalSession.id }); // Return URL as JSON
  } catch (err) {
    console.error(err);
    res.status(500).send("Stripe portal session creation failed");
  }
});

// POST /webhook - Handle Stripe webhooks
app.post(
  "/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    let event;
    const endpointSecret = process.env.STRIPE_ENDPOINT_SECRET;
    const signature = req.headers["stripe-signature"];
    try {
      // req.body is already a Buffer because of express.raw()
      event = await stripe.webhooks.constructEventAsync(
        req.rawBody,
        signature,
        endpointSecret
      );
    } catch (err) {
      console.error("Webhook signature verification failed:", err.message);
      return res.sendStatus(400);
    }

    // Extract common fields
    const subscription = event.data.object;
    const stripeID = subscription.customer;
    const email = subscription.metadata.email;

    // Helper function to update the user record
    const updateUserSubscription = async (email, stripeID, periodEnd, status) => {
      const user = await users.findOne({ email });
      if (!user) {
        console.log(`No user found with email: ${email}`);
        return;
      }
      
      await users.updateOne(
        { email },
        { $set: { stripeID, expires: periodEnd, subStatus: status } }
      );
      
      console.log(`Updated user ${user.email} => stripeID: ${stripeID}, expires: ${periodEnd}, subStatus: ${status}`);
    };

    try {
      switch (event.type) {
        case "customer.subscription.deleted":
          console.log(`Processing DELETED event for ${email} with status ${subscription.status}`);
          await updateUserSubscription(email, stripeID, subscription.current_period_end, subscription.status);
          break;
        case "customer.subscription.updated":
          console.log(`Processing UPDATED event for ${email} with status ${subscription.status}`);
          await updateUserSubscription(email, stripeID, subscription.current_period_end, subscription.status);
          break;
        default:
          console.log(`Unhandled event type ${event.type}`);
      }
    } catch (error) {
      console.error("Error processing subscription event:", error.message);
      return res.sendStatus(500);
    }
    res.sendStatus(200);
  }
);

app.listen(Deno.env.get("PORT"), () =>
  console.log(`Express server running on port ${Deno.env.get("PORT")}`)
);

// Cleanup on exit
Deno.addSignalListener("SIGINT", async () => {
  await client.close();
  Deno.exit();
});
