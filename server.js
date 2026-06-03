//  server.js  —  REST Web API на Node.js
//  Функции: регистрация, логин, CRUD пользователей,
//           поиск, пагинация, статистика
//  Безопасность: JWT, bcrypt, rate-limiting

var express    = require("express");
var bodyParser = require("body-parser");
var jwt        = require("jsonwebtoken");
var bcrypt     = require("bcryptjs");
var cors       = require("cors");
var rateLimit  = require("express-rate-limit");
var fs         = require("fs");
var path       = require("path");

var app = express();
var JWT_SECRET = "super_secret_key_change_in_production_2024";

// ── Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, "public")));

// ── Rate Limiting
var globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: "Слишком много запросов. Попробуйте через 15 минут." },
    standardHeaders: true,
    legacyHeaders: false
});

// Строгий лимит для авторизации: 10 попыток / 15 минут
var authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: { error: "Слишком много попыток входа. Попробуйте позже." }
});

app.use("/api/auth/login", authLimiter);
app.use("/api/auth/register", authLimiter);

// ── Helpers: чтение/запись JSON-файлов
function readJSON(filename) {
    var filePath = path.join(__dirname, "data", filename);
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
}
function writeJSON(filename, data) {
    var filePath = path.join(__dirname, "data", filename);
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

// ── Middleware: проверка JWT токена
function authenticate(req, res, next) {
    var authHeader = req.headers["authorization"];
    if (!authHeader) return res.status(401).json({ error: "Токен не передан" });

    var token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : authHeader;
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (e) {
        return res.status(401).json({ error: "Токен недействителен или истёк" });
    }
}

// Только для администратора
function requireAdmin(req, res, next) {
    if (req.user.role !== "admin")
        return res.status(403).json({ error: "Доступ запрещён: требуется роль admin" });
    next();
}


//  1. POST /api/auth/register  —  Регистрация нового аккаунта
app.post("/api/auth/register", function(req, res) {
    if (!req.body || !req.body.username || !req.body.password)
        return res.status(400).json({ error: "Укажите username и password" });

    var accounts = readJSON("accounts.json");
    var exists = accounts.find(a => a.username === req.body.username);
    if (exists) return res.status(409).json({ error: "Пользователь уже существует" });

    var hash = bcrypt.hashSync(req.body.password, 10);
    var maxId = accounts.reduce((m, a) => Math.max(m, a.id), 0);
    var newAccount = {
        id: maxId + 1,
        username: req.body.username,
        passwordHash: hash,
        role: "user"
    };
    accounts.push(newAccount);
    writeJSON("accounts.json", accounts);

    res.status(201).json({ message: "Аккаунт создан", username: newAccount.username });
});

//  2. POST /api/auth/login  —  Авторизация, выдача JWT
app.post("/api/auth/login", function(req, res) {
    if (!req.body || !req.body.username || !req.body.password)
        return res.status(400).json({ error: "Укажите username и password" });

    var accounts = readJSON("accounts.json");
    var account = accounts.find(a => a.username === req.body.username);
    if (!account || !bcrypt.compareSync(req.body.password, account.passwordHash))
        return res.status(401).json({ error: "Неверный логин или пароль" });

    var token = jwt.sign(
        { id: account.id, username: account.username, role: account.role },
        JWT_SECRET,
        { expiresIn: "2h" }
    );
    res.json({ token: token, role: account.role, username: account.username, expiresIn: "2h" });
});

//  3. GET /api/users  —  Список пользователей (пагинация + поиск)
app.get("/api/users", authenticate, function(req, res) {
    var users = readJSON("users.json");

    // Поиск по имени
    if (req.query.search) {
        var q = req.query.search.toLowerCase();
        users = users.filter(u => u.name.toLowerCase().includes(q) ||
                                  u.email.toLowerCase().includes(q));
    }

    // Сортировка: ?sort=name|age|id  &order=asc|desc
    if (req.query.sort) {
        var field = req.query.sort;
        var order = req.query.order === "desc" ? -1 : 1;
        users.sort((a, b) => (a[field] > b[field] ? 1 : -1) * order);
    }

    var total = users.length;

    // Пагинация: ?page=1&limit=10
    var page  = parseInt(req.query.page)  || 1;
    var limit = parseInt(req.query.limit) || 10;
    var start = (page - 1) * limit;
    var paged = users.slice(start, start + limit);

    res.json({
        total: total,
        page: page,
        limit: limit,
        pages: Math.ceil(total / limit),
        data: paged
    });
});

//  4. GET /api/users/:id  —  Один пользователь по ID
app.get("/api/users/:id", authenticate, function(req, res) {
    var users = readJSON("users.json");
    var user  = users.find(u => u.id == req.params.id);
    if (!user) return res.status(404).json({ error: "Пользователь не найден" });
    res.json(user);
});

//  5. POST /api/users  —  Создать пользователя (admin only)
app.post("/api/users", authenticate, requireAdmin, function(req, res) {
    if (!req.body || !req.body.name || !req.body.age || !req.body.email)
        return res.status(400).json({ error: "Укажите name, age и email" });

    var users = readJSON("users.json");
    var emailExists = users.find(u => u.email === req.body.email);
    if (emailExists) return res.status(409).json({ error: "Email уже используется" });

    var maxId = users.reduce((m, u) => Math.max(m, u.id), 0);
    var user  = {
        id: maxId + 1,
        name: req.body.name,
        age: parseInt(req.body.age),
        email: req.body.email,
        role: req.body.role || "user",
        createdAt: new Date().toISOString()
    };
    users.push(user);
    writeJSON("users.json", users);
    res.status(201).json(user);
});

//  6. PUT /api/users/:id  —  Обновить пользователя
app.put("/api/users/:id", authenticate, function(req, res) {
    if (!req.body) return res.status(400).json({ error: "Тело запроса пустое" });

    var users = readJSON("users.json");
    var idx   = users.findIndex(u => u.id == req.params.id);
    if (idx === -1) return res.status(404).json({ error: "Пользователь не найден" });

    // Обычный пользователь может менять только себя
    if (req.user.role !== "admin" && users[idx].email !== req.user.username)
        return res.status(403).json({ error: "Нет прав для редактирования" });

    users[idx] = Object.assign({}, users[idx], {
        name:  req.body.name  || users[idx].name,
        age:   req.body.age   ? parseInt(req.body.age) : users[idx].age,
        email: req.body.email || users[idx].email,
        role:  req.user.role === "admin" ? (req.body.role || users[idx].role) : users[idx].role
    });
    writeJSON("users.json", users);
    res.json(users[idx]);
});

//  7. DELETE /api/users/:id  —  Удалить пользователя (admin)
app.delete("/api/users/:id", authenticate, requireAdmin, function(req, res) {
    var users = readJSON("users.json");
    var idx   = users.findIndex(u => u.id == req.params.id);
    if (idx === -1) return res.status(404).json({ error: "Пользователь не найден" });

    var removed = users.splice(idx, 1)[0];
    writeJSON("users.json", users);
    res.json({ message: "Пользователь удалён", user: removed });
});

//  8. GET /api/users/stats/summary  —  Статистика по пользователям
app.get("/api/stats/summary", authenticate, function(req, res) {
    var users = readJSON("users.json");
    var totalAge = users.reduce((s, u) => s + u.age, 0);
    var roles = users.reduce((acc, u) => {
        acc[u.role] = (acc[u.role] || 0) + 1;
        return acc;
    }, {});
    var ageGroups = {
        "18-25": users.filter(u => u.age >= 18 && u.age <= 25).length,
        "26-35": users.filter(u => u.age >= 26 && u.age <= 35).length,
        "36-50": users.filter(u => u.age >= 36 && u.age <= 50).length,
        "50+":   users.filter(u => u.age > 50).length
    };
    res.json({
        total: users.length,
        averageAge: users.length ? (totalAge / users.length).toFixed(1) : 0,
        minAge: users.length ? Math.min(...users.map(u => u.age)) : 0,
        maxAge: users.length ? Math.max(...users.map(u => u.age)) : 0,
        roles: roles,
        ageGroups: ageGroups
    });
});

//  9. GET /api/profile  —  Профиль текущего авторизованного
app.get("/api/profile", authenticate, function(req, res) {
    res.json({
        id: req.user.id,
        username: req.user.username,
        role: req.user.role,
        message: "Вы успешно авторизованы"
    });
});

// ── 404 для неизвестных API-маршрутов ──────────────────────
app.use("/api/{*path}", function(req, res) {
    res.status(404).json({ error: "Маршрут не найден" });
});

// ── Запуск сервера ──────────────────────────────────────────
app.listen(3000, function() {
    console.log("✅  Сервер запущен: http://localhost:3000");
    console.log("📌  API доступен по: http://localhost:3000/api");
    console.log("🔑  Тестовые данные: admin / secret");
});