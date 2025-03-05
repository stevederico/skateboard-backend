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
    name TEXT NOT NULL
  )
`);

// Stripe initialization (replace with your actual key)
const stripe = new Stripe(Deno.env.get("STRIPE_KEY"));
const appURL = Deno.env.get("APP_URL")

// JWT helper: Generates a token for a given userId
async function generateToken(userId) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode("secret"),
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
      const responseObj = { id: user.id, email: user.email, name: user.name, token };
      return res.json(responseObj);
    }
    res.status(401).json({ error: "Invalid credentials" });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// GET /users - Protected route to list all users
app.get("/users", async (req, res) => {
  try {
    const authHeader = req.headers["authorization"];
    if (!authHeader) throw new Error("Unauthorized");
    const token = authHeader.split(" ")[1];
    // Import the same key used in generateToken for verification
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode("secret"),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign", "verify"]
    );
    await verify(token, key);
    const users = [...db.query("SELECT id, email FROM users")].map(([id, email]) => ({ id, email }));
    res.json(users);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Serve static files from the 'public' directory
app.use(express.static("public"));

// POST /create-checkout-session - Create a Stripe checkout session
app.post("/create-checkout-session", async (req, res) => {
  try {
    const prices = await stripe.prices.list({
      lookup_keys: [req.body.lookup_key],
      expand: ["data.product"],
    });
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
      success_url: `${appURL}/?success=true&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${appURL}/?canceled=true`,
    });
    res.status(200).json({ url: session.url, id: session.id }); // Return URL as JSON
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Stripe session creation failed" });
  }
});

// POST /create-portal-session - Create a Stripe billing portal session
app.post("/create-portal-session", async (req, res) => {
  try {
    const { customerID } = req.body;
    const portalSession = await stripe.billingPortal.sessions.create({
      customer: customerID,
      return_url: `${appURL}/?portal=return`,
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
    let event = req.body;
    const endpointSecret = Deno.env.get("STRIPE_ENDPOINT_SECRET");
    if (endpointSecret) {
      const signature = req.headers["stripe-signature"];
      try {
        event = await stripe.webhooks.constructEventAsync(
          req.rawBody,
          signature,
          endpointSecret
        );
      } catch (err) {
        console.log(`⚠️  Webhook signature verification failed.`, err.message);
        return res.sendStatus(400);
      }
    }
    switch (event.type) {
      case 'checkout.session.completed': {
        const session = event.data.object;
        if (session.payment_status === 'paid' && session.customer) {
          // Here you have the customer ID
          const customerId = session.customer;

          //write customerId to database

          // Do something with customerId (store it, send it somewhere, etc.)
          console.log('Successful payment, Customer ID:', customerId);
        }
        break;
      }
      case "customer.subscription.trial_will_end": {
        const subscription = event.data.object;
        console.log(`Subscription status is ${subscription.status}.`);
        break;
      }
      case "customer.subscription.deleted": {
        const subscription = event.data.object;
        console.log(`Subscription status is ${subscription.status}.`);
        break;
      }
      case "customer.subscription.created": {
        const subscription = event.data.object;
        console.log(`Subscription status is ${subscription.status}.`);
        break;
      }
      case "customer.subscription.updated": {
        const subscription = event.data.object;
        console.log(`Subscription status is ${subscription.status}.`);
        break;
      }
      case "entitlements.active_entitlement_summary.updated": {
        const subscription = event.data.object;
        console.log(`Active entitlement summary updated for ${subscription}.`);
        break;
      }
      default:
        console.log(`Unhandled event type ${event.type}.`);
    }
    res.send();
  }
);

// Start Express server on port 

app.listen(Deno.env.get("PORT"), () =>
  console.log(`Express server running on port ${Deno.env.get("PORT")}`)
);

app.get("/test", async (req, res) => {
  res.json({"status": "hello"})
})

// Cleanup on exit
Deno.addSignalListener("SIGINT", () => {
  db.close();
  Deno.exit();
});
