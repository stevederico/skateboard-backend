// Import necessary modules
import { DB } from "https://deno.land/x/sqlite/mod.ts";
import { serve } from "https://deno.land/std/http/server.ts";
import { create, verify } from "https://deno.land/x/djwt/mod.ts";
import * as bcrypt from "https://deno.land/x/bcrypt/mod.ts";

// Initialize SQLite database
const db = new DB("my_database.db");

// Create users table with the updated schema
db.execute(`
   CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    name TEXT NOT NULL
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
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });   // Handle CORS
  const path = new URL(req.url).pathname;

  try {
    switch (path) {
      case "/signup": {
        if (req.method !== "POST") break;
      
        try {
          const { email, password, name } = JSON.parse(await req.text());
          const trimmedEmail = email?.trim();
          const trimmedName = name?.trim();
      
          if (!trimmedEmail || !password?.trim() || !trimmedName) {
            return new Response(
              JSON.stringify({ error: "Missing required fields" }),
              { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
            );
          }
      
          const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
          if (!emailRegex.test(trimmedEmail)) {
            return new Response(
              JSON.stringify({ error: "Invalid email format" }),
              { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
            );
          }
      
          const existingUser = [...db.query("SELECT * FROM users WHERE email = ?", [trimmedEmail])];
          if (existingUser.length > 0) {
            return new Response(
              JSON.stringify({ error: "Email already exists" }),
              { status: 409, headers: { ...corsHeaders, "Content-Type": "application/json" } }
            );
          }
      
          const salt = await bcrypt.genSalt(12);
          const hash = await bcrypt.hash(password, salt);
      
          await db.query(
            "INSERT INTO users (email, password, name) VALUES (?, ?, ?)",
            [trimmedEmail, hash, trimmedName]
          );
          const userId = db.lastInsertRowId;
      
          const [newUserRow] = [...db.query("SELECT id, email, name FROM users WHERE id = ?", [userId])];
          const token = await generateToken(userId);
          const responseObj = { id: newUserRow[0], email: newUserRow[1], name: newUserRow[2], token };
      
          return new Response(JSON.stringify(responseObj), {
            status: 201,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          });
        } catch (error) {
          return new Response(
            JSON.stringify({ error: "Internal server error", details: error.message }),
            { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
          );
        }
      }
      
      // POST /signin - Authenticate user
      case "/signin": {
        if (req.method !== "POST") break;
        if (!req.headers.get("Content-Type")?.includes("application/json")) {
          throw new Error("Content-Type must be application/json");
        }

        const body = await req.json();
        const { email, password } = body;
        if (!email || !password) {
          throw new Error("Email and password are required");
        }

        const [user] = [...db.queryEntries("SELECT * FROM users WHERE email = ?", [email.trim()])];

        if (user && await bcrypt.compare(password, user.password)) {
          const token = await generateToken(user.id);
          var responseObj = { 'email': user.email, 'id': user.id, 'name': user.name, 'token': token }
          return new Response(JSON.stringify(responseObj), {
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          });
        }

        // Explicit response for invalid credentials
        return new Response(JSON.stringify({ error: "Invalid credentials" }), {
          status: 401, // Unauthorized status code
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
      // GET /users - List all users (protected)
      case "/users": {
        if (req.method !== "GET") break;
        const token = req.headers.get("Authorization")?.split(" ")[1];
        if (!token) throw new Error("Unauthorized");

        await verify(token, await generateToken());
        const users = [...db.query("SELECT id, email FROM users")].map(([id, email]) => ({ id, email }));
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
