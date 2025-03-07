// @deno-types="npm:@types/express"
import { Hono } from "https://deno.land/x/hono@v3.10.0/mod.ts";
import { cors } from "https://deno.land/x/hono@v3.10.0/middleware.ts";
import { serve } from "https://deno.land/std@0.195.0/http/server.ts";
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

// Create Hono app
const app = new Hono();

// CORS middleware
app.use("*", cors({
  origin: "*",
  allowMethods: ["POST", "GET", "OPTIONS"],
  allowHeaders: ["Content-Type", "Authorization"],
}));

// Root route
app.get("/", async (c) => {
  try {
    const file = await Deno.readFile("./public/index.html");
    return new Response(file, {
      headers: {
        "Content-Type": "text/html",
      },
    });
  } catch (e) {
    return c.text("Welcome to Skateboard API", 200);
  }
});

// Middleware to store raw body for Stripe webhook
app.use("/webhook", async (c, next) => {
  const rawBody = await c.req.raw.clone().arrayBuffer();
  c.set("rawBody", rawBody);
  await next();
});

// Serve static files from the 'public' directory
app.use("/public/*", async (c) => {
  const path = c.req.path.replace("/public/", "");
  try {
    const file = await Deno.readFile(`./public/${path}`);
    const mimeType = getMimeType(path);
    return new Response(file, {
      headers: {
        "Content-Type": mimeType,
      },
    });
  } catch (e) {
    return c.notFound();
  }
});

function getMimeType(path) {
  const ext = path.split(".").pop()?.toLowerCase();
  const mimeTypes = {
    html: "text/html",
    css: "text/css",
    js: "text/javascript",
    json: "application/json",
    png: "image/png",
    jpg: "image/jpeg",
    jpeg: "image/jpeg",
    gif: "image/gif",
    svg: "image/svg+xml",
  };
  return mimeTypes[ext] || "application/octet-stream";
}

// Health check endpoint
app.get("/health", (c) => {
  return c.json({
    status: "ok",
    timestamp: Date.now()
  });
});

// POST /signup - Create a new user
app.post("/signup", async (c) => {
  try {
    const body = await c.req.json();
    const { email, password, name } = body;
    const trimmedEmail = email?.trim();
    const trimmedName = name?.trim();

    if (!trimmedEmail || !password?.trim() || !trimmedName) {
      return c.json({ error: "Missing required fields" }, 400);
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(trimmedEmail)) {
      return c.json({ error: "Invalid email format" }, 400);
    }

    const existingUser = await users.findOne({ email: trimmedEmail });
    if (existingUser) {
      return c.json({ error: "Email already exists" }, 409);
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
    
    return c.json({
      id: newUser._id.toString(),
      email: newUser.email,
      name: newUser.name,
      token
    }, 201);
  } catch (error) {
    return c.json({ error: "Internal server error", details: error.message }, 500);
  }
});

// POST /signin - Authenticate user
app.post("/signin", async (c) => {
  try {
    if (!c.req.header("content-type")?.includes("application/json")) {
      throw new Error("Content-Type must be application/json");
    }
    
    const body = await c.req.json();
    const { email, password } = body;
    
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
      return c.json(responseObj);
    }
    return c.json({ error: "Invalid credentials" }, 401);
  } catch (error) {
    return c.json({ error: error.message }, 400);
  }
});

app.get("/me", async (c) => {
  try {
    // Get and validate authorization header
    const authHeader = c.req.header("authorization");
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return c.json({ error: "Unauthorized: No valid token provided" }, 401);
    }

    const token = authHeader.split(" ")[1];
    if (!token) {
      return c.json({ error: "Unauthorized: Token missing" }, 401);
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
      return c.json({ error: "Unauthorized: Invalid token payload" }, 401);
    }

    // Fetch user from database
    const user = await users.findOne({ _id: new ObjectId(userId) });

    if (!user) {
      return c.json({ error: "User not found" }, 404);
    }

    // Return user details (excluding password)
    return c.json({
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
      return c.json({ error: "Unauthorized: Invalid token" }, 401);
    }
    return c.json({ error: "Internal server error" }, 500);
  }
});

// GET /isSubscriber - Check if the user is a subscriber
app.get("/isSubscriber", async (c) => {
  try {
    // Get and validate authorization header
    const authHeader = c.req.header("authorization");
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return c.json({ error: "Unauthorized: No valid token provided" }, 401);
    }

    const token = authHeader.split(" ")[1];
    if (!token) {
      return c.json({ error: "Unauthorized: Token missing" }, 401);
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
      return c.json({ error: "Unauthorized: Invalid token payload" }, 401);
    }

    // Fetch user subscription status from database
    const user = await users.findOne(
      { _id: new ObjectId(userId) },
      { projection: { stripeID: 1, expires: 1, subStatus: 1 } }
    );

    if (!user) {
      return c.json({ error: "User not found" }, 404);
    }

    // Check if user has an active subscription
    const isSubscriber = user.stripeID && 
                         user.subStatus === "active" && 
                         (!user.expires || user.expires > Math.floor(Date.now() / 1000));

    return c.json({ 
      isSubscriber,
      subscriptionDetails: {
        status: user.subStatus,
        expiresAt: user.expires ? new Date(user.expires * 1000).toISOString() : null
      }
    });
  } catch (error) {
    console.error("Error in /isSubscriber endpoint:", error.message);
    if (error.name === "JWTError") {
      return c.json({ error: "Unauthorized: Invalid token" }, 401);
    }
    return c.json({ error: "Internal server error" }, 500);
  }
});

// POST /create-checkout-session - Create a Stripe checkout session
app.post("/create-checkout-session", async (c) => {
  try {
    const body = await c.req.json();
    const prices = await stripe.prices.list({
      lookup_keys: [body.lookup_key],
      expand: ["data.product"],
    });

    // Get the origin from the request headers
    const origin = c.req.header("origin");
    if (!origin) {
      return c.json({ error: "Missing Origin header" }, 400);
    }

    const session = await stripe.checkout.sessions.create({
      customer_email: body.email,
      mode: "subscription",
      payment_method_types: ['card'],
      line_items: [
        {
          price: prices.data[0].id,
          quantity: 1,
        },
      ],
      billing_address_collection: 'auto',
      success_url: `${origin}/app/stripe?success=true`,
      cancel_url: `${origin}/app/stripe?canceled=true`,
      subscription_data: {
        metadata: {
          email: body.email,
        },
      },
    });

    return c.json({ url: session.url, id: session.id, customerID: session.customer });
  } catch (err) {
    console.error(err);
    return c.json({ error: "Stripe session creation failed" }, 500);
  }
});

// POST /create-portal-session - Create a Stripe billing portal session
app.post("/create-portal-session", async (c) => {
  // Get the origin from the request headers
  const origin = c.req.header("origin");
  if (!origin) {
    return c.json({ error: "Missing Origin header" }, 400);
  }

  try {
    const body = await c.req.json();
    const { customerID } = body;
    const portalSession = await stripe.billingPortal.sessions.create({
      customer: customerID,
      return_url: `${origin}/app/stripe?portal=return`,
    });
    console.log("/create-portal-session ", portalSession.url);
    return c.json({ url: portalSession.url, id: portalSession.id });
  } catch (err) {
    console.error(err);
    return c.json({ error: "Stripe portal session creation failed" }, 500);
  }
});

// POST /webhook - Handle Stripe webhooks
app.post("/webhook", async (c) => {
  let event;
  const endpointSecret = Deno.env.get("STRIPE_ENDPOINT_SECRET");
  const signature = c.req.header("stripe-signature");
  
  try {
    // Get the raw body from middleware
    const rawBody = c.get("rawBody");
    event = await stripe.webhooks.constructEventAsync(
      rawBody,
      signature,
      endpointSecret
    );
  } catch (err) {
    console.error("Webhook signature verification failed:", err.message);
    return new Response(null, { status: 400 });
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
    return new Response(null, { status: 500 });
  }
  
  return new Response(null, { status: 200 });
});

// Start the server
const port = parseInt(Deno.env.get("PORT") || "8000");
console.log(`Hono server running on port ${port}`);

serve(app.fetch, { port });

// Cleanup on exit
Deno.addSignalListener("SIGINT", async () => {
  await client.close();
  Deno.exit();
});
