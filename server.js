const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const axios = require('axios');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();
const PORT = 3000;
const SECRET_KEY = "12345"; // JWT Vulnerable: Clave extremadamente débil

// Middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static('public')); // Para cargar el frontend (lo haremos luego)

// Configuración de Base de Datos SQLite en memoria
const db = new sqlite3.Database(':memory:');
db.serialize(() => {
    db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT, is_vip BOOLEAN)");
    db.run("INSERT INTO users (username, password, role, is_vip) VALUES ('admin', 'admin123', 'admin', true)");
    db.run("INSERT INTO users (username, password, role, is_vip) VALUES ('carlos', 'qwerty', 'user', false)");
    
    db.run("CREATE TABLE invoices (id INTEGER PRIMARY KEY, user_id INTEGER, amount TEXT, details TEXT)");
    db.run("INSERT INTO invoices (user_id, amount, details) VALUES (1, '$5000', 'Compra Servidores')");
    db.run("INSERT INTO invoices (user_id, amount, details) VALUES (2, '$50', 'Suscripción básica')");
});

// ==========================================
// 1. INYECCIÓN SQL (SQLi)
// ==========================================
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    // VULNERABILIDAD: Concatenación directa sin parametrizar
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    
    db.get(query, (err, user) => {
        if (err || !user) return res.status(401).send("Credenciales inválidas");
        
        // Genera JWT
        const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, SECRET_KEY);
        res.cookie('session', token); // Vulnerable a CSRF al no tener SameSite Strict
        res.json({ message: "Login exitoso", token });
    });
});

// ==========================================
// 2. CROSS-SITE SCRIPTING (XSS Reflejado)
// ==========================================
app.get('/api/search', (req, res) => {
    const query = req.query.q;
    // VULNERABILIDAD: Refleja la entrada del usuario directamente en el HTML sin sanitizar
    res.send(`<h1>Resultados de búsqueda para: ${query}</h1><p>No se encontraron resultados.</p>`);
});

// ==========================================
// 3. SERVER-SIDE REQUEST FORGERY (SSRF)
// ==========================================
app.post('/api/fetch-image', async (req, res) => {
    // VULNERABILIDAD: Pide datos a cualquier URL externa sin lista blanca
    try {
        const response = await axios.get(req.body.url);
        res.send(response.data);
    } catch (error) {
        res.status(500).send("Error al obtener la imagen remota");
    }
});

// ==========================================
// 4. MASS ASSIGNMENT & IDOR
// ==========================================
app.put('/api/users/profile', (req, res) => {
    const token = req.cookies.session;
    if (!token) return res.status(401).send("No autenticado");

    const decoded = jwt.verify(token, SECRET_KEY);
    let updatedData = req.body; // VULNERABILIDAD: Acepta todo el payload (Mass Assignment)

    // Actualiza inyectando directamente los campos (Ej. "role": "admin")
    const query = `UPDATE users SET role = '${updatedData.role || decoded.role}', is_vip = ${updatedData.is_vip || false} WHERE id = ${decoded.id}`;
    db.run(query, (err) => {
        if (err) return res.status(500).send("Error actualizando");
        res.send("Perfil actualizado (Mass Assignment exitoso)");
    });
});

app.get('/api/invoices/:id', (req, res) => {
    const invoiceId = req.params.id;
    // VULNERABILIDAD IDOR: No verifica si la factura pertenece al usuario logueado
    db.get(`SELECT * FROM invoices WHERE id = ${invoiceId}`, (err, row) => {
        if (row) res.json(row);
        else res.status(404).send("Factura no encontrada");
    });
});

// Iniciar servidor
app.listen(PORT, () => {
    console.log(`Servidor vulnerable corriendo en http://localhost:${PORT}`);
}); 