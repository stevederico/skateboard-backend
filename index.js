// Import necessary modules
import { DB } from "https://deno.land/x/sqlite/mod.ts";
import { serve } from "https://deno.land/std/http/server.ts";
import { create, verify } from "https://deno.land/x/djwt/mod.ts";
import * as bcrypt from "https://deno.land/x/bcrypt/mod.ts";

// Create a new database
const db = new DB("my_database.db");

try {
  // Drop existing table if exists
  db.execute("DROP TABLE IF EXISTS users");
  // Create table with proper schema
  db.execute(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    )
  `);
  console.log("Database initialized successfully");
} catch (error) {
  console.error("Database initialization failed:", error);
}

// CORS headers
const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

// Validate email and password
function validateInput(email, password) {
  if (!email || typeof email !== "string" || !email.includes("@")) {
    throw new Error("Invalid email format");
  }
  if (!password || typeof password !== "string" || password.length < 1) {
    throw new Error("Invalid password");
  }
}

// Helper: Import the secret into a CryptoKey
async function getCryptoKey() {
  const keyData = new TextEncoder().encode("secret");
  return await crypto.subtle.importKey(
    "raw",
    keyData,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

// REST endpoint
serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  const path = new URL(req.url).pathname;
  console.log(`${req.method} ${path}`);

  // Signup route
  if (path === "/signup" && req.method === "POST") {
    try {
      const body = await req.json();
      const { email, password } = body;
      const validEmail = email.trim();
      validateInput(validEmail, password);
      console.log("Signup attempt for:", validEmail);

      const hashedPassword = await bcrypt.hash(password);
      db.query("INSERT INTO users (email, password) VALUES (?, ?)", [validEmail, hashedPassword]);

      const rows = [...db.queryEntries("SELECT last_insert_rowid() AS id")];
      if (!rows.length) {
        throw new Error("Could not fetch last inserted id");
      }
      const { id } = rows[0];
      console.log("User ID:", id);

      const cryptoKey = await getCryptoKey();
      const token = await create(
        { alg: "HS256", typ: "JWT" },
        { userId: id },
        cryptoKey
      );

      console.log("Signup successful for:", validEmail);
      return new Response(JSON.stringify({ token }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    } catch (error) {
      console.error("Signup failed:", error);
      const errorMessage =
        error.message === "Invalid email format" || error.message === "Invalid password"
          ? error.message
          : "Email already exists";
      return new Response(JSON.stringify({ error: errorMessage }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
  }

  // Signin route
  if (path === "/signin" && req.method === "POST") {
    try {
      const body = await req.json();
      const { email, password } = body;
      const validEmail = email.trim();
      validateInput(validEmail, password);
      console.log("Signin attempt for:", validEmail);

      // Get user record by trimmed email
      const [user] = [...db.queryEntries("SELECT * FROM users WHERE email = ?", [validEmail])];
      if (user && await bcrypt.compare(password, user.password)) {
        const cryptoKey = await getCryptoKey();
        // Use the user's id from the DB record
        const token = await create(
          { alg: "HS256", typ: "JWT" },
          { userId: user.id },
          cryptoKey
        );
        console.log("Signin successful for:", validEmail);
        return new Response(JSON.stringify({ token }), {
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
      console.log("Signin failed for:", validEmail);
      return new Response(JSON.stringify({ error: "Invalid credentials" }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    } catch (error) {
      console.error("Signin error:", error);
      const errorMessage =
        error.message === "Invalid email format" || error.message === "Invalid password"
          ? error.message
          : "Server error";
      return new Response(JSON.stringify({ error: errorMessage }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
  }

  // Protected /users route
  if (path === "/users" && req.method === "GET") {
    const authHeader = req.headers.get("Authorization");
    const token = authHeader?.split(" ")[1];
    if (!token) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
    try {
      const cryptoKey = await getCryptoKey();
      await verify(token, cryptoKey);

      const users = [...db.query("SELECT id, email FROM users")].map(
        ([id, email]) => ({ id, email })
      );
      return new Response(JSON.stringify(users), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    } catch (error) {
      console.error("Token verification failed:", error);
      return new Response(JSON.stringify({ error: "Invalid token" }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
  }

  return new Response(JSON.stringify({ error: "Not found" }), {
    status: 404,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
});

// Gracefully close the database on SIGINT
Deno.addSignalListener("SIGINT", () => {
  db.close();
  Deno.exit();
});
