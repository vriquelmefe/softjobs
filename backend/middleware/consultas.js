require("dotenv").config();
const jwt = require("jsonwebtoken");
const SECRET_KEY = process.env.SECRET_KEY; // Extraje la clave secreta del entorno

const verifyCredentials = (req, res, next) => {
  const { email, password } = req.body;
  if (!email || !password) {

    return res.status(400).send({ message: 'Email y contraseña son obligatorios.' });
  }
  next();
};


const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization; 
  if (!authHeader || !authHeader.startsWith('Bearer ')) {

    return res.status(401).send({ message: 'Token no proporcionado o inválido.' });
  }
  const token = authHeader.split(' ')[1]; 
  try {
    const decoded = jwt.verify(token, SECRET_KEY); 
    req.email = decoded.email;
    next();
  } catch (error) {
    res.status(401).send({ message: 'Token inválido o expirado.' }); 
  }
};  


module.exports = { verifyCredentials, verifyToken };