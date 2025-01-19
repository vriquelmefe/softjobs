require("dotenv").config();
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");

const { verifyCredentials, verifyToken } = require("./middleware/consultas");

const pool = new Pool({
  user: "postgres",
  host: "localhost",
  database: "softjobs",
  password: process.env.DB_PASSWORD,
  port: 5433,
});

pool.query("SELECT NOW()", (err, res) => {
  if (err) {
    console.error("Error en la conexion a la base de datos:", err);
    process.exit(1);
  } else {
    console.log("se ha conectado a la base de datos", res.rows);
  }
});


const app = express();
const SECRET_KEY = process.env.SECRET_KEY;

app.use(express.json());
app.use(cors());

app.post("/usuarios", verifyCredentials, async (req, res) => {
  try {
    const { email, password, rol, lenguage } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 10);
    const query =
      "INSERT INTO usuarios (email, password, rol, lenguage) VALUES ($1, $2, $3, $4)";
    await pool.query(query, [email, hashedPassword, rol, lenguage]);
    res.status(201).send({ message: "Usuario registrado con éxito." });
  } catch (error) {
    console.error("Error al registrar usuario:", error);
    res.status(500).send({ message: "Error al registrar usuario.", error });
  }
});
app.post("/login", verifyCredentials, async (req, res) => {
  try {
    const { email, password } = req.body;
    const query = "SELECT * FROM usuarios WHERE email = $1";
    const { rows } = await pool.query(query, [email]);

    if (rows.length === 0 || !bcrypt.compareSync(password, rows[0].password)) {
      return res
        .status(401)
        .send({ message: "Email o contraseña incorrectos." });
    }

    const token = jwt.sign({ email }, SECRET_KEY, { expiresIn: "1h" });
    res.send({ token });
  } catch (error) {
    console.error("Error al iniciar sesión:", error);
    res.status(500).send({ message: "Error al iniciar sesión.", error });
  }
});

app.get("/usuarios", verifyToken, async (req, res) => {
  try {
    const query = "SELECT * FROM usuarios WHERE email = $1";
    const { rows } = await pool.query(query, [req.email]);

    if (rows.length === 0) {
      return res.status(404).send({ message: "Usuario no encontrado." });
    }

    res.send(rows);
  } catch (error) {
    console.error("Error al obtener usuario:", error);
    res.status(500).send({ message: "Error al obtener usuario.", error });
  }
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});