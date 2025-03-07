// @deno-types="npm:@types/express"
import { Hono } from "https://deno.land/x/hono@v3.10.0/mod.ts";
import { cors } from "https://deno.land/x/hono@v3.10.0/middleware.ts";
import { serve } from "https://deno.land/std@0.195.0/http/server.ts";
import { MongoClient, ObjectId } from "npm:mongodb";
import Stripe from "npm:stripe";
import { create, verify } from "https://deno.land/x/djwt/mod.ts";
import * as bcrypt from "https://deno.land/x/bcrypt/mod.ts";
import { load } from "https://deno.land/std@0.195.0/dotenv/mod.ts";

// Load environment variables
try {
  await load({ export: true });
  if (!Deno.env.get("MONGODB_URI") || !Deno.env.get("STRIPE_KEY") || !Deno.env.get("JWT_SECRET")) {
    throw new Error("Missing required environment variables");
  }
} catch (e) {
  console.error("Failed to load environment variables:", e.message);
  Deno.exit(1);
}

// MongoDB setup
const client = new MongoClient(Deno.env.get("MONGODB_URI"));
try {
  await client.connect();
} catch (e) {
  console.error("MongoDB connection failed:", e.message);
  Deno.exit(1);
}
const db = client.db("SkateboardApp");
const users = db.collection("Users");
const auths = db.collection("Auths");
await users.createIndex({ email: 1 }, { unique: true });

// Stripe setup
const stripe = new Stripe(Deno.env.get("STRIPE_KEY"));

// JWT helpers
const jwtKey = await crypto.subtle.importKey(
  "raw",
  new TextEncoder().encode(Deno.env.get("JWT_SECRET")),
  { name: "HMAC", hash: "SHA-256" },
  false,
  ["sign", "verify"]
);

async function generateToken(userId) {
  return create({ alg: "HS256", typ: "JWT" }, { userId }, jwtKey);
}

async function authMiddleware(c, next) {
  const authHeader = c.req.header("authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) return c.json({ error: "Unauthorized" }, 401);
  const token = authHeader.split(" ")[1];
  try {
    const payload = await verify(token, jwtKey);
    c.set("userId", payload.userId);
    await next();
  } catch {
    return c.json({ error: "Invalid token" }, 401);
  }
}

// Hono app
const app = new Hono();
app.use("*", cors({ origin: Deno.env.get("CORS_ORIGIN") || "*", allowMethods: ["POST", "GET", "OPTIONS"], allowHeaders: ["Content-Type", "Authorization"] }));

app.get("/", async (c) => {
  try {
    const file = await Deno.readFile("./public/index.html");
    return new Response(file, { headers: { "Content-Type": "text/html" } });
  } catch {
    return c.text("Welcome to Skateboard API", 200);
  }
});

app.use("/webhook", async (c, next) => {
  c.set("rawBody", await c.req.raw.clone().arrayBuffer());
  await next();
});

app.use("/public/*", async (c) => {
  const path = c.req.path.replace("/public/", "");
  try {
    const file = await Deno.readFile(`./public/${path}`);
    return new Response(file, { headers: { "Content-Type": getMimeType(path) } });
  } catch {
    return c.notFound();
  }
});

function getMimeType(path) {
  const ext = path.split(".").pop()?.toLowerCase();
  const mimeTypes = { html: "text/html", css: "text/css", js: "text/javascript", json: "application/json", png: "image/png", jpg: "image/jpeg", gif: "image/gif", svg: "image/svg+xml" };
  return mimeTypes[ext] || "application/octet-stream";
}

app.get("/health", (c) => c.json({ status: "ok", timestamp: Date.now() }));

app.post("/signup", async (c) => {
  try {
    const { email, password, name } = await c.req.json();
    const trimmedEmail = email?.trim();
    if (!trimmedEmail || !password?.trim() || !name?.trim() || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmedEmail)) {
      return c.json({ error: "Invalid input" }, 400);
    }
    
    const hash = await bcrypt.hash(password, await bcrypt.genSalt(12));
    const { insertedId } = await users.insertOne({
      email: trimmedEmail,
      name: name.trim(),
      created_at: Date.now(),
      subscription: { stripeID: null, expires: null, status: null }
    });
    await auths.insertOne({ email: trimmedEmail, password: hash, userID: insertedId });
    
    const token = await generateToken(insertedId.toString());
    return c.json({ id: insertedId.toString(), email: trimmedEmail, name: name.trim(), token }, 201);
  } catch (e) {
    if (e.code === 11000) return c.json({ error: "Email exists" }, 409);
    console.error("Signup error:", e.message);
    return c.json({ error: "Server error" }, 500);
  }
});

app.post("/signin", async (c) => {
  try {
    if (!c.req.header("content-type")?.includes("application/json")) {
      return c.json({ error: "Invalid content type" }, 400);
    }
    const { email, password } = await c.req.json();
    if (!email || !password) return c.json({ error: "Missing credentials" }, 400);
    
    const auth = await auths.findOne({ email: email.trim() });
    if (!auth || !(await bcrypt.compare(password, auth.password))) return c.json({ error: "Invalid credentials" }, 401);
    
    const user = await users.findOne({ _id: auth.userID });
    if (!user) return c.json({ error: "User not found" }, 404);
    
    const token = await generateToken(user._id.toString());
    return c.json({
      id: user._id.toString(),
      email: user.email,
      name: user.name,
      subscription: { stripeID: user.subscription?.stripeID || null, expires: user.subscription?.expires || null, status: user.subscription?.status || null },
      token
    });
  } catch (e) {
    console.error("Signin error:", e.message);
    return c.json({ error: "Server error" }, 500);
  }
});

app.get("/me", authMiddleware, async (c) => {
  const user = await users.findOne({ _id: new ObjectId(c.get("userId")) });
  if (!user) return c.json({ error: "User not found" }, 404);
  return c.json({
    id: user._id.toString(),
    email: user.email,
    name: user.name,
    subscription: { stripeID: user.subscription?.stripeID || null, expires: user.subscription?.expires || null, status: user.subscription?.status || null }
  });
});

app.get("/isSubscriber", authMiddleware, async (c) => {
  const user = await users.findOne(
    { _id: new ObjectId(c.get("userId")) },
    { projection: { "subscription.stripeID": 1, "subscription.expires": 1, "subscription.status": 1 } }
  );
  if (!user) return c.json({ error: "User not found" }, 404);
  
  const isSubscriber = user.subscription?.stripeID && user.subscription?.status === "active" && (!user.subscription?.expires || user.subscription.expires > Math.floor(Date.now() / 1000));
  return c.json({
    isSubscriber,
    subscription: {
      status: user.subscription?.status || null,
      expiresAt: user.subscription?.expires ? new Date(user.subscription.expires * 1000).toISOString() : null
    }
  });
});

app.post("/create-checkout-session", authMiddleware, async (c) => {
  try {
    const { email, lookup_key } = await c.req.json();
    if (!email || !lookup_key) return c.json({ error: "Missing email or lookup_key" }, 400);
    
    // Verify the email matches the authenticated user
    const user = await users.findOne({ _id: new ObjectId(c.get("userId")) });
    if (!user || user.email !== email) return c.json({ error: "Email mismatch" }, 403);
    
    const prices = await stripe.prices.list({ lookup_keys: [lookup_key], expand: ["data.product"] });
    const origin = c.req.header("origin") || Deno.env.get("APP_ORIGIN") || "http://localhost:8000";
    
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
    return c.json({ url: session.url, id: session.id, customerID: session.customer });
  } catch (e) {
    console.error("Checkout session error:", e.message);
    return c.json({ error: "Stripe session failed" }, 500);
  }
});

app.post("/create-portal-session", authMiddleware, async (c) => {
  try {
    const { customerID } = await c.req.json();
    if (!customerID) return c.json({ error: "Missing customerID" }, 400);
    
    // Verify the customerID matches the authenticated user's subscription
    const user = await users.findOne({ _id: new ObjectId(c.get("userId")) });
    if (!user || (user.subscription?.stripeID && user.subscription.stripeID !== customerID)) {
      return c.json({ error: "Unauthorized customerID" }, 403);
    }
    
    const origin = c.req.header("origin") || Deno.env.get("APP_ORIGIN") || "http://localhost:8000";
    const portalSession = await stripe.billingPortal.sessions.create({
      customer: customerID,
      return_url: `${origin}/app/stripe?portal=return`,
    });
    return c.json({ url: portalSession.url, id: portalSession.id });
  } catch (e) {
    console.error("Portal session error:", e.message);
    return c.json({ error: "Stripe portal failed" }, 500);
  }
});

app.post("/webhook", async (c) => {
  const signature = c.req.header("stripe-signature");
  let event;
  try {
    event = await stripe.webhooks.constructEventAsync(c.get("rawBody"), signature, Deno.env.get("STRIPE_ENDPOINT_SECRET"));
  } catch (e) {
    console.error("Webhook signature verification failed:", e.message);
    return new Response(null, { status: 400 });
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
  return new Response(null, { status: 200 });
});

// Server start
const port = parseInt(Deno.env.get("PORT") || "8000");
console.log(`Server running on port ${port}`);
serve(app.fetch, { port });

Deno.addSignalListener("SIGINT", async () => {
  await client.close();
  Deno.exit();
});