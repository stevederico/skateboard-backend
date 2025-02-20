// Import necessary modules
import { DB } from "https://deno.land/x/sqlite/mod.ts";
import { serve } from "https://deno.land/std/http/server.ts";
import { create, verify } from "https://deno.land/x/djwt/mod.ts";
import * as bcrypt from "https://deno.land/x/bcrypt/mod.ts";

// Initialize SQLite database
const db = new DB("my_database.db");

// Create users table
db.execute(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
  )
`);

// CORS configuration
const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

// JWT helper
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

// API Server
serve(async (req) => {
  // Handle CORS
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

  const path = new URL(req.url).pathname;

  try {
    switch (path) {
      // POST /signup - Create new user
      case "/signup": {
        if (req.method !== "POST") break;
        const { email, password } = await req.json();
        const hash = await bcrypt.hash(password);
        db.query("INSERT INTO users (email, password) VALUES (?, ?)", [email.trim(), hash]);
        const token = await generateToken(db.lastInsertRowId);
        return new Response(JSON.stringify({ token }), {
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }

      // POST /signin - Authenticate user
      case "/signin": {
        if (req.method !== "POST") break;
        const { email, password } = await req.json();
        const [user] = [...db.queryEntries("SELECT * FROM users WHERE email = ?", [email.trim()])];
        
        if (user && await bcrypt.compare(password, user.password)) {
          const token = await generateToken(user.id);
          return new Response(JSON.stringify({ token }), {
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          });
        }
        throw new Error("Invalid credentials");
      }

      // GET /users - List all users (protected)
      case "/users": {
        if (req.method !== "GET") break;
        const token = req.headers.get("Authorization")?.split(" ")[1];
        if (!token) throw new Error("Unauthorized");
        
        await verify(token, await generateToken());
        const users = [...db.query("SELECT id, email FROM users")].map(([id, email]) => ({id, email}));
        return new Response(JSON.stringify(users), {
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
    }

    return new Response(JSON.stringify({ error: "Not found" }), { 
      status: 404,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });

  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 400,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});

// Cleanup on exit
Deno.addSignalListener("SIGINT", () => {
  db.close();
  Deno.exit();
});
