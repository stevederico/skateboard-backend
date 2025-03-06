// @deno-types="npm:@types/express"
import express from "npm:express";
import { DB } from "https://deno.land/x/sqlite/mod.ts";
import { create, verify } from "https://deno.land/x/djwt/mod.ts";
import * as bcrypt from "https://deno.land/x/bcrypt/mod.ts";
import Stripe from "stripe";
import { load } from "https://deno.land/std@0.195.0/dotenv/mod.ts";

await load({ export: true });

// Initialize SQLite database
const db = new DB("my_database.db");

// Create users table if it doesn't exist
db.execute(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    name TEXT NOT NULL,
    stripeID TEXT,
    expires INTEGER,
    subStatus TEXT
  )
`);

// Stripe initialization (replace with your actual key)
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

    const existingUser = [...db.query("SELECT * FROM users WHERE email = ?", [trimmedEmail])];
    if (existingUser.length > 0) {
      return res.status(409).json({ error: "Email already exists" });
    }

    const salt = await bcrypt.genSalt(12);
    const hash = await bcrypt.hash(password, salt);

    db.query(
      "INSERT INTO users (email, password, name) VALUES (?, ?, ?)",
      [trimmedEmail, hash, trimmedName]
    );
    const userId = db.lastInsertRowId;
    const [newUserRow] = [...db.query("SELECT id, email, name FROM users WHERE id = ?", [userId])];
    const token = await generateToken(userId);
    const responseObj = { id: newUserRow[0], email: newUserRow[1], name: newUserRow[2], token };

    res.status(201).json(responseObj);
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

    const [user] = [...db.queryEntries("SELECT * FROM users WHERE email = ?", [email.trim()])];
    if (user && (await bcrypt.compare(password, user.password))) {
      const token = await generateToken(user.id);
      const responseObj = { id: user.id, email: user.email, name: user.name, stripeID: user.stripeID, expires: user.expires, subStatus: user.subStatus, token: token };
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
      new TextEncoder().encode("secret"),
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
    const [user] = [...db.queryEntries(
      "SELECT id, email, name, stripeID, expires, subStatus FROM users WHERE id = ?",
      [userId]
    )];

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Return user details (excluding password)
    res.json({
      id: user.id,
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
      success_url: `${origin}/app/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${origin}/app?canceled=true`,
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
      return_url: `${origin}/?portal=return`,
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
      const [user] = [...db.queryEntries("SELECT * FROM users WHERE email = ?", [email])];
      if (!user) {
        console.log(`No user found with email: ${email}`);
        return;
      }
      db.query(
        "UPDATE users SET stripeID = ?, expires = ?, subStatus = ? WHERE email = ?",
        [stripeID, periodEnd, status, email]
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
Deno.addSignalListener("SIGINT", () => {
  db.close();
  Deno.exit();
});
