import express from "npm:express";
import { MongoClient, ObjectId } from "npm:mongodb";
import Stripe from "npm:stripe";
import { create, verify } from "https://deno.land/x/djwt/mod.ts";
import * as bcrypt from "https://deno.land/x/bcrypt/mod.ts";
import { readFile } from "node:fs/promises";
import { dirname, resolve, fromFileUrl } from "https://deno.land/std@0.195.0/path/mod.ts";
import { cron } from "https://deno.land/x/deno_cron/cron.ts";

// Load config
let config;
try {
  const configPath = resolve(dirname(fromFileUrl(import.meta.url)), './config.json');
  const configData = await readFile(configPath, 'utf-8');
  config = JSON.parse(configData);
} catch (err) {
  console.error('Failed to load config:', err);
  config = [{ db: "SkateboardApp", origin: "http://localhost:3000" }];
}

// Always load env first
if (!isProd()) {
  loadLocalENV();
} else {
  cron("Scheduled Task", "0 * * * *", async () => {
    console.log(`Hourly Completed at ${new Date().toLocaleTimeString()}`);
  });

}

// Load environment variables after loadLocalENV completes
const MONGO_URI = Deno.env.get("MONGO_URI");
const STRIPE_KEY = Deno.env.get("STRIPE_KEY");
const JWT_SECRET = Deno.env.get("JWT_SECRET");

if (!MONGO_URI || !STRIPE_KEY || !JWT_SECRET) {
  console.error("Missing required environment variables");
  Deno.exit(1);
}

// Stripe setup
const stripe = new Stripe(STRIPE_KEY);

// MongoDB setup
const mongoUri = MONGO_URI.trim();
if (!mongoUri) {
  console.error("MongoDB URI is empty or undefined");
  Deno.exit(1);
}
if (!mongoUri.startsWith("mongodb://") && !mongoUri.startsWith("mongodb+srv://")) {
  console.error("Invalid MongoDB URI scheme. URI must start with mongodb:// or mongodb+srv://");
  Deno.exit(1);
}

const client = new MongoClient(mongoUri);
try {
  await client.connect();
} catch (e) {
  console.error("MongoDB connection failed:", e.message);
  process.exit(1);
}

// Get database name based on origin
const getDBName = (origin) => {
  const configEntry = config.find(entry => entry.origin === origin) || config[0];
  const dbName = configEntry.db;
  console.log(`Using database: ${dbName} for origin: ${origin}`);
  return dbName;
};

// Initialize db and collections
let db;
let users;
let auths;

// Express app initialization
const app = express();
const allowedOrigins = config.map(entry => entry.origin);

// CORS and database middleware
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  }
  res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  next();
});

// Database switching middleware
app.use((req, res, next) => {
  const origin = req.headers.origin || 'default';
  if (!db || db.databaseName !== getDBName(origin)) {
    db = client.db(getDBName(origin));
    users = db.collection("Users");
    auths = db.collection("Auths");
  }
  next();
});

app.use(express.json());

// Create indexes on first startup
const initialDb = client.db(config[0].db);
await initialDb.collection("Users").createIndex({ email: 1 }, { unique: true });
await initialDb.collection("Auths").createIndex({ email: 1 }, { unique: true });

// ==== STATIC ====
app.use("/public", express.static("./public"));

app.get("/", async (req, res) => {
  try {
    const file = await readFile("./public/index.html");
    res.setHeader("Content-Type", "text/html");
    res.send(file);
  } catch {
    res.status(200).send("Welcome to Skateboard API");
  }
});

app.get("/health", (req, res) => res.json({ status: "ok", timestamp: Date.now() }));

// ==== AUTH ====
app.post("/signup", async (req, res) => {
  try {
    const { email, password, name } = req.body;
    const trimmedEmail = email?.trim();
    if (!trimmedEmail || !password?.trim() || !name?.trim() || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmedEmail)) {
      return res.status(400).json({ error: "Invalid input" });
    }

    const hash = await bcrypt.hash(password, await bcrypt.genSalt(12));
    const { insertedId } = await users.insertOne({
      email: trimmedEmail,
      name: name.trim(),
      created_at: Date.now()
    });
    await auths.insertOne({ email: trimmedEmail, password: hash, userID: insertedId });

    const token = await generateToken(insertedId.toString());
    res.status(201).json({ id: insertedId.toString(), email: trimmedEmail, name: name.trim(), token });
  } catch (e) {
    if (e.code === 11000) return res.status(409).json({ error: "Email exists" });
    console.error("Signup error:", e.message);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/signin", async (req, res) => {
  try {
    if (!req.headers["content-type"]?.includes("application/json")) {
      return res.status(400).json({ error: "Invalid content type" });
    }
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Missing credentials" });

    const auth = await auths.findOne({ email: email.trim() });
    if (!auth || !(await bcrypt.compare(password, auth.password))) return res.status(401).json({ error: "Invalid credentials" });

    const user = await users.findOne({ _id: auth.userID });
    if (!user) return res.status(404).json({ error: "User not found" });

    const token = await generateToken(user._id.toString());
    res.json({
      id: user._id.toString(),
      email: user.email,
      name: user.name,
      ...(user.subscription && {
        subscription: {
          stripeID: user.subscription.stripeID,
          expires: user.subscription.expires,
          status: user.subscription.status,
        },
      }),
      token,
    });
  } catch (e) {
    console.error("Signin error:", e.message);
    res.status(500).json({ error: "Server error" });
  }
});

// JWT helpers
const jwtKey = await crypto.subtle.importKey(
  "raw",
  new TextEncoder().encode(JWT_SECRET),
  { name: "HMAC", hash: "SHA-256" },
  false,
  ["sign", "verify"]
);

async function generateToken(userId) {
  return create({ alg: "HS256", typ: "JWT" }, { userId }, jwtKey);
}

async function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) return res.status(401).json({ error: "Unauthorized" });
  const token = authHeader.split(" ")[1];
  try {
    const payload = await verify(token, jwtKey);
    req.userId = payload.userId;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// ==== USER-DATA ====
app.get("/me", authMiddleware, async (req, res) => {
  const user = await users.findOne({ _id: new ObjectId(req.userId) });
  if (!user) return res.status(404).json({ error: "User not found" });
  res.json({
    id: user._id.toString(),
    email: user.email,
    name: user.name,
    ...(user.subscription && {
      subscription: {
        stripeID: user.subscription.stripeID,
        expires: user.subscription.expires,
        status: user.subscription.status,
      },
    }),
  });
});

app.get("/isSubscriber", authMiddleware, async (req, res) => {
  const user = await users.findOne(
    { _id: new ObjectId(req.userId) },
    { projection: { "subscription.stripeID": 1, "subscription.expires": 1, "subscription.status": 1 } }
  );
  if (!user) return res.status(404).json({ error: "User not found" });

  const isSubscriber = user.subscription?.stripeID && user.subscription?.status === "active" && (!user.subscription?.expires || user.subscription.expires > Math.floor(Date.now() / 1000));
  res.json({
    isSubscriber,
    subscription: {
      status: user.subscription?.status || null,
      expiresAt: user.subscription?.expires ? new Date(user.subscription.expires * 1000).toISOString() : null
    }
  });
});

// ==== STRIPE ====
app.post("/create-checkout-session", authMiddleware, async (req, res) => {
  try {
    const { email, lookup_key } = req.body;
    if (!email || !lookup_key) return res.status(400).json({ error: "Missing email or lookup_key" });

    // Verify the email matches the authenticated user
    const user = await users.findOne({ _id: new ObjectId(req.userId) });
    if (!user || user.email !== email) return res.status(403).json({ error: "Email mismatch" });

    const prices = await stripe.prices.list({ lookup_keys: [lookup_key], expand: ["data.product"] });
    const origin = req.headers.origin || Deno.env.get("APP_ORIGIN") || "http://localhost:8000";

    const session = await stripe.checkout.sessions.create({
      customer_email: email,
      mode: "subscription",
      payment_method_types: ["card"],
      line_items: [{ price: prices.data[0].id, quantity: 1 }],
      billing_address_collection: "auto",
      success_url: `${origin}/app/stripe?success=true`,
      cancel_url: `${origin}/app/stripe?canceled=true`,
      subscription_data: { metadata: { email } },
    });
    res.json({ url: session.url, id: session.id, customerID: session.customer });
  } catch (e) {
    console.error("Checkout session error:", e.message);
    res.status(500).json({ error: "Stripe session failed" });
  }
});

app.post("/create-portal-session", authMiddleware, async (req, res) => {
  try {
    const { customerID } = req.body;
    if (!customerID) return res.status(400).json({ error: "Missing customerID" });

    // Verify the customerID matches the authenticated user's subscription
    const user = await users.findOne({ _id: new ObjectId(req.userId) });
    if (!user || (user.subscription?.stripeID && user.subscription.stripeID !== customerID)) {
      return res.status(403).json({ error: "Unauthorized customerID" });
    }

    const origin = req.headers.origin || Deno.env.get("APP_ORIGIN") || "http://localhost:8000";
    const portalSession = await stripe.billingPortal.sessions.create({
      customer: customerID,
      return_url: `${origin}/app/stripe?portal=return`,
    });
    res.json({ url: portalSession.url, id: portalSession.id });
  } catch (e) {
    console.error("Portal session error:", e.message);
    res.status(500).json({ error: "Stripe portal failed" });
  }
});

app.post("/webhook", express.raw({ type: "application/json" }), async (req, res) => {
  const signature = req.headers["stripe-signature"];
  let event;
  try {
    event = await stripe.webhooks.constructEvent(req.body, signature, Deno.env.get("STRIPE_ENDPOINT_SECRET"));
  } catch (e) {
    console.error("Webhook signature verification failed:", e.message);
    return res.status(400).send();
  }

  const { customer: stripeID, metadata: { email }, current_period_end, status } = event.data.object;
  if (["customer.subscription.deleted", "customer.subscription.updated"].includes(event.type)) {
    console.log(`Webhook: ${event.type} for ${email}`);
    const user = await users.findOne({ email });
    if (user) {
      await users.updateOne({ email }, { $set: { subscription: { stripeID, expires: current_period_end, status } } });
    } else {
      console.warn(`Webhook: No user found for email ${email}`);
    }
  }
  res.status(200).send();
});

//==== MISC ====
function isProd() {
  if (typeof Deno.env.get("ENV") === "undefined") {
    return false
  } else if (Deno.env.get("ENV") === "production") {
    return true
  } else {
    return false
  }
}

function loadLocalENV() {
  console.log("LOCAL ENV");
  const __dirname = dirname(fromFileUrl(import.meta.url));
  const envFilePath = resolve(__dirname, './.env');
  try {
    const data = Deno.readTextFileSync(envFilePath);
    const lines = data.split(/\r?\n/);
    for (let line of lines) {
      if (!line || line.trim().startsWith('#')) continue;

      // Split only on first = and handle quoted values
      let [key, ...valueParts] = line.split('=');
      let value = valueParts.join('='); // Rejoin in case value contains =

      if (key && value) {
        key = key.trim();
        value = value.trim();
        // Remove surrounding quotes if present
        value = value.replace(/^["']|["']$/g, '');
        Deno.env.set(key, value);
      }
    }
  } catch (err) {
    console.error('Failed to load .env file:', err);
  }
}

// Server start
const port = parseInt(Deno.env.get("PORT") || "8000");

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

// Handle shutdown gracefully
Deno.addSignalListener("SIGINT", async () => {
  console.log("Shutting down...");
  await client.close();
  Deno.exit();
});