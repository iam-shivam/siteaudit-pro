import { pbkdf2Sync, randomBytes } from "node:crypto";

const ITERATIONS = 210_000;
const terminal = process.stdin.isTTY;

const password = await new Promise((resolve, reject) => {
  let value = "";
  const finish = (error) => {
    process.stdin.removeListener("data", onData);
    if (terminal) process.stdin.setRawMode(false);
    process.stdin.pause();
    error ? reject(error) : resolve(value.replace(/[\r\n]+$/, ""));
  };
  const onData = (chunk) => {
    value += chunk;
    if (value.includes("\u0003")) finish(new Error("Cancelled."));
    else if (value.length > 512) finish(new Error("Password input is too long."));
    else if (value.includes("\n") || value.includes("\r")) finish();
  };
  if (terminal) {
    process.stdin.setRawMode(true);
    process.stderr.write("Ready for administrator password on stdin (input is hidden).\n");
  }
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", onData);
  process.stdin.resume();
});

if (!password) throw new Error("Password is required.");
const salt = randomBytes(16);
const derived = pbkdf2Sync(password, salt, ITERATIONS, 32, "sha256");
const encode = (value) => value.toString("base64url");

process.stdout.write(`${JSON.stringify({
  passwordHash: `pbkdf2-sha256$${ITERATIONS}$${encode(salt)}$${encode(derived)}`,
  sessionSecret: encode(randomBytes(32)),
})}\n`);
