const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3000

// Middlewares
app.use(cors());
app.use(express.json());

// Conexão com o Banco de Dados SQLite Relacional
// Um ficheiro chamado 'database.db' será criado automaticamente na pasta do projeto
const db = new sqlite3.Database('./database.db', (err) => {
    if (err) {
        console.error("Erro ao conectar ao SQLite:", err.message);
    } else {
        console.log("Conectado com sucesso ao banco de dados SQLite do Study.ia.");
    }
});

// Criação da tabela de utilizadores utilizando SQL estruturado
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
        console.log("Tabela 'users' modelada e pronta para armazenamento dinâmico.");
    }
});

// ROTA DE REGISTO (Cadastro de Novos Vestibulandos)
app.post('/api/register', async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ error: "Todos os campos são obrigatórios." });
    }

    try {
        // Encriptação da password para segurança da informação
        const hashedPassword = await bcrypt.hash(password, 10);

        // Inserção lógica dos dados na tabela SQL relacionais
        const sql = `INSERT INTO users (name, email, password) VALUES (?, ?, ?)`;
        db.run(sql, [name, email, hashedPassword], function(err) {
            if (err) {
                // Validação de restrição de email único
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

// ROTA DE LOGIN (Autenticação de Usuários)
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "Email e password são obrigatórios." });
    }

    const sql = `SELECT * FROM users WHERE email = ?`;
    db.get(sql, [email], async (err, user) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (!user) {
            return res.status(400).json({ error: "Credenciais incorretas ou utilizador inexistente." });
        }

        // Comparação da password enviada com o hash encriptado guardado na base de dados
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

// Inicialização do Servidor Local
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Servidor do Study.ia rodando com sucesso na porta ${PORT}`);
});
