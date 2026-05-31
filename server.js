const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middlewares
app.use(cors());
app.use(express.json());

// Força o caminho do banco de dados a ser estável em qualquer ambiente
const dbPath = path.resolve(__dirname, 'database.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error("Erro ao conectar ao SQLite:", err.message);
    } else {
        console.log("Conectado com sucesso ao banco de dados SQLite do Study.ia.");
    }
});

// Criação da tabela de utilizadores
db.run(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
`, (err) => {
    if (err) {
        console.error("Erro ao criar a tabela de utilizadores:", err.message);
    } else {
        console.log("Tabela 'users' pronta para uso.");
    }
});

// ROTA DE REGISTO
app.post('/api/register', async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ error: "Todos os campos são obrigatórios." });
    }

    // Tratamento para evitar problemas com espaços ou letras maiúsculas no e-mail
    const emailFormatado = email.trim().toLowerCase();

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const sql = `INSERT INTO users (name, email, password) VALUES (?, ?, ?)`;
        
        db.run(sql, [name.trim(), emailFormatado, hashedPassword], function(err) {
            if (err) {
                if (err.message.includes("UNIQUE constraint failed")) {
                    return res.status(400).json({ error: "Este email já está registado no sistema." });
                }
                return res.status(500).json({ error: err.message });
            }
            res.status(201).json({ 
                message: "Utilizador registado com sucesso!", 
                userId: this.lastID 
            });
        });
    } catch (error) {
        res.status(500).json({ error: "Erro interno no servidor backend." });
    }
});

// ROTA DE LOGIN 
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "Email e password são obrigatórios." });
    }

    const emailFormatado = email.trim().toLowerCase();
    const sql = `SELECT * FROM users WHERE email = ?`;

    db.get(sql, [emailFormatado], async (err, user) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (!user) {
            return res.status(400).json({ error: "Credenciais incorretas ou utilizador inexistente." });
        }

        // Comparação da password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ error: "Credenciais incorretas ou utilizador inexistente." });
        }

        // Sucesso na Autenticação
        res.json({ 
            message: "Login efetuado com sucesso!", 
            user: { id: user.id, name: user.name, email: user.email } 
        });
    });
});

// Rota raiz para evitar o erro "Cannot GET /" quando acessar o link puro
app.get('/', (req, res) => {
    res.send("API do Study.ia está online e rodando!");
});

// Inicialização do Servidor
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});
