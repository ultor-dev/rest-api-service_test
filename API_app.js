/**
 * REST API сервис на Node.js
 * 
 * Функции:
 * 1. Получение списка пользователей (GET /api/users)
 * 2. Получение пользователя по ID (GET /api/users/:id)
 * 3. Создание нового пользователя (POST /api/users)
 * 4. Обновление пользователя (PUT /api/users/:id)
 * 5. Удаление пользователя (DELETE /api/users/:id)
 * 6. Регистрация (POST /api/auth/register)
 * 7. Авторизация (POST /api/auth/login)
 * 8. Получение профиля (GET /api/auth/profile)
 * 9. Поиск пользователей (GET /api/users/search)
 * 10. Статистика запросов (GET /api/stats)
 * 11. Пагинация пользователей (GET /api/users?page=1&limit=10)
 * 12. Частичное обновление (PATCH /api/users/:id)
 * 
 * Авторизация: JWT токены
 * Лимитирование: Ограничение запросов от одного пользователя
 */

var express = require("express");
var bodyParser = require("body-parser");
var fs = require("fs");
var path = require("path");

// Импорт модулей
var auth = require("./auth");
var rateLimiter = require("./rateLimiter");

var app = express();
var jsonParser = bodyParser.json();

// Статические файлы
app.use(express.static(__dirname + "/public"));

// Middleware для логирования запросов
app.use(function(req, res, next) {
    const start = Date.now();
    res.on('finish', () => {
        const duration = Date.now() - start;
        console.log(`${new Date().toISOString()} | ${req.method} ${req.url} | ${res.statusCode} | ${duration}ms`);
    });
    next();
});

// Глобальный rate limiter
app.use(rateLimiter.rateLimiter({
    getUserId: (req) => req.headers['x-forwarded-for'] || req.ip
}));

// ==================== МАРШРУТЫ АВТОРИЗАЦИИ ====================

/**
 * Функция 6: Регистрация нового пользователя
 * POST /api/auth/register
 */
app.post("/api/auth/register", jsonParser, function(req, res) {
    if (!req.body) {
        return res.status(400).json({ error: 'Тело запроса не может быть пустым' });
    }

    const { username, password, email } = req.body;

    // Валидация
    if (!username || !password || !email) {
        return res.status(400).json({
            error: 'Validation Error',
            message: 'Все поля обязательны: username, password, email'
        });
    }

    if (username.length < 3) {
        return res.status(400).json({
            error: 'Validation Error',
            message: 'Имя пользователя должно содержать минимум 3 символа'
        });
    }

    if (password.length < 6) {
        return res.status(400).json({
            error: 'Validation Error',
            message: 'Пароль должен содержать минимум 6 символов'
        });
    }

    const result = auth.register({ username, password, email });

    if (result.success) {
        res.status(201).json({
            message: 'Пользователь успешно зарегистрирован',
            user: result.user
        });
    } else {
        res.status(409).json({ error: result.message });
    }
});

/**
 * Функция 7: Авторизация пользователя
 * POST /api/auth/login
 */
app.post("/api/auth/login", jsonParser, function(req, res) {
    if (!req.body) {
        return res.status(400).json({ error: 'Тело запроса не может быть пустым' });
    }

    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({
            error: 'Validation Error',
            message: 'Необходимо указать username и password'
        });
    }

    const result = auth.login(username, password);

    if (result.success) {
        res.json({
            message: 'Авторизация успешна',
            token: result.token,
            user: result.user,
            expiresIn: result.expiresIn
        });
    } else {
        res.status(401).json({ error: result.message });
    }
});

/**
 * Функция 8: Получение профиля текущего пользователя
 * GET /api/auth/profile
 */
app.get("/api/auth/profile", auth.authMiddleware(), function(req, res) {
    res.json({
        message: 'Профиль пользователя',
        user: {
            userId: req.userId,
            username: req.username,
            role: req.userRole
        }
    });
});

/**
 * Получение списка пользователей аутентификации (только для админов)
 * GET /api/auth/users
 */
app.get("/api/auth/users", auth.authMiddleware({ roles: ['admin'] }), function(req, res) {
    const users = auth.getAuthUsers();
    res.json({
        count: users.length,
        users: users
    });
});

// ==================== МАРШРУТЫ ПОЛЬЗОВАТЕЛЕЙ ====================

/**
 * Функция 1: Получение списка пользователей с пагинацией
 * GET /api/users?page=1&limit=10&sort=name&order=asc
 */
app.get("/api/users", auth.authMiddleware(), function(req, res) {
    var content = fs.readFileSync("users.json", "utf8");
    var users = JSON.parse(content);

    // Пагинация
    var page = parseInt(req.query.page) || 1;
    var limit = parseInt(req.query.limit) || 10;
    var sort = req.query.sort || 'id';
    var order = req.query.order || 'asc';

    // Сортировка
    users.sort(function(a, b) {
        var aVal = a[sort];
        var bVal = b[sort];

        if (typeof aVal === 'string') {
            aVal = aVal.toLowerCase();
            bVal = bVal.toLowerCase();
        }

        if (order === 'desc') {
            return aVal > bVal ? -1 : aVal < bVal ? 1 : 0;
        }
        return aVal > bVal ? 1 : aVal < bVal ? -1 : 0;
    });

    // Пагинация
    var total = users.length;
    var totalPages = Math.ceil(total / limit);
    var startIndex = (page - 1) * limit;
    var endIndex = startIndex + limit;
    var paginatedUsers = users.slice(startIndex, endIndex);

    res.json({
        data: paginatedUsers,
        pagination: {
            currentPage: page,
            totalPages: totalPages,
            totalItems: total,
            itemsPerPage: limit,
            hasNextPage: page < totalPages,
            hasPrevPage: page > 1
        }
    });
});

/**
 * Функция 2: Получение одного пользователя по ID
 * GET /api/users/:id
 */
app.get("/api/users/:id", auth.authMiddleware(), function(req, res) {
    var id = req.params.id;
    var content = fs.readFileSync("users.json", "utf8");
    var users = JSON.parse(content);
    var user = null;

    for (var i = 0; i < users.length; i++) {
        if (users[i].id == id) {
            user = users[i];
            break;
        }
    }

    if (user) {
        res.json(user);
    } else {
        res.status(404).json({
            error: 'Not Found',
            message: 'Пользователь с ID ' + id + ' не найден'
        });
    }
});

/**
 * Функция 9: Поиск пользователей
 * GET /api/users/search?q=query&field=name
 */
app.get("/api/users/search", auth.authMiddleware(), function(req, res) {
    var query = req.query.q;
    var field = req.query.field || 'name';

    if (!query) {
        return res.status(400).json({
            error: 'Validation Error',
            message: 'Параметр поиска "q" обязателен'
        });
    }

    var content = fs.readFileSync("users.json", "utf8");
    var users = JSON.parse(content);

    var results = users.filter(function(user) {
        var value = user[field];
        if (typeof value === 'string') {
            return value.toLowerCase().includes(query.toLowerCase());
        }
        return String(value).toLowerCase().includes(query.toLowerCase());
    });

    res.json({
        query: query,
        field: field,
        count: results.length,
        results: results
    });
});

/**
 * Функция 3: Создание нового пользователя
 * POST /api/users
 */
app.post("/api/users", auth.authMiddleware(), jsonParser, function(req, res) {
    if (!req.body) {
        return res.status(400).json({ error: 'Тело запроса не может быть пустым' });
    }

    var userName = req.body.name;
    var userAge = req.body.age;
    var userEmail = req.body.email;

    // Валидация
    if (!userName) {
        return res.status(400).json({
            error: 'Validation Error',
            message: 'Поле "name" обязательно'
        });
    }

    if (userAge !== undefined && (typeof userAge !== 'number' || userAge < 0 || userAge > 150)) {
        return res.status(400).json({
            error: 'Validation Error',
            message: 'Поле "age" должно быть числом от 0 до 150'
        });
    }

    var user = {
        name: userName,
        age: userAge,
        email: userEmail,
        createdBy: req.username,
        createdAt: new Date().toISOString()
    };

    var data = fs.readFileSync("users.json", "utf8");
    var users = JSON.parse(data);

    // Находим максимальный id
    var id = Math.max.apply(Math, users.map(function(o) { return o.id; }));
    user.id = id + 1;

    users.push(user);
    var newData = JSON.stringify(users, null, 2);
    fs.writeFileSync("users.json", newData);

    res.status(201).json({
        message: 'Пользователь успешно создан',
        user: user
    });
});

/**
 * Функция 4: Полное обновление пользователя
 * PUT /api/users/:id
 */
app.put("/api/users/:id", auth.authMiddleware(), jsonParser, function(req, res) {
    if (!req.body) {
        return res.status(400).json({ error: 'Тело запроса не может быть пустым' });
    }

    var id = req.params.id;
    var userName = req.body.name;
    var userAge = req.body.age;
    var userEmail = req.body.email;

    // Валидация
    if (!userName) {
        return res.status(400).json({
            error: 'Validation Error',
            message: 'Поле "name" обязательно'
        });
    }

    var data = fs.readFileSync("users.json", "utf8");
    var users = JSON.parse(data);
    var user = null;
    var userIndex = -1;

    for (var i = 0; i < users.length; i++) {
        if (users[i].id == id) {
            user = users[i];
            userIndex = i;
            break;
        }
    }

    if (user) {
        // Обновляем все поля
        users[userIndex] = {
            id: user.id,
            name: userName,
            age: userAge,
            email: userEmail,
            createdAt: user.createdAt,
            updatedAt: new Date().toISOString(),
            updatedBy: req.username
        };

        var newData = JSON.stringify(users, null, 2);
        fs.writeFileSync("users.json", newData);

        res.json({
            message: 'Пользователь успешно обновлён',
            user: users[userIndex]
        });
    } else {
        res.status(404).json({
            error: 'Not Found',
            message: 'Пользователь с ID ' + id + ' не найден'
        });
    }
});

/**
 * Функция 12: Частичное обновление пользователя
 * PATCH /api/users/:id
 */
app.patch("/api/users/:id", auth.authMiddleware(), jsonParser, function(req, res) {
    if (!req.body) {
        return res.status(400).json({ error: 'Тело запроса не может быть пустым' });
    }

    var id = req.params.id;
    var data = fs.readFileSync("users.json", "utf8");
    var users = JSON.parse(data);
    var user = null;
    var userIndex = -1;

    for (var i = 0; i < users.length; i++) {
        if (users[i].id == id) {
            user = users[i];
            userIndex = i;
            break;
        }
    }

    if (user) {
        // Обновляем только переданные поля
        var allowedFields = ['name', 'age', 'email'];
        for (var field of allowedFields) {
            if (req.body[field] !== undefined) {
                users[userIndex][field] = req.body[field];
            }
        }

        users[userIndex].updatedAt = new Date().toISOString();
        users[userIndex].updatedBy = req.username;

        var newData = JSON.stringify(users, null, 2);
        fs.writeFileSync("users.json", newData);

        res.json({
            message: 'Пользователь успешно обновлён',
            user: users[userIndex]
        });
    } else {
        res.status(404).json({
            error: 'Not Found',
            message: 'Пользователь с ID ' + id + ' не найден'
        });
    }
});

/**
 * Функция 5: Удаление пользователя
 * DELETE /api/users/:id
 */
app.delete("/api/users/:id", auth.authMiddleware({ roles: ['admin'] }), function(req, res) {
    var id = req.params.id;
    var data = fs.readFileSync("users.json", "utf8");
    var users = JSON.parse(data);
    var index = -1;

    for (var i = 0; i < users.length; i++) {
        if (users[i].id == id) {
            index = i;
            break;
        }
    }

    if (index > -1) {
        var user = users.splice(index, 1)[0];
        var newData = JSON.stringify(users, null, 2);
        fs.writeFileSync("users.json", newData);

        res.json({
            message: 'Пользователь успешно удалён',
            user: user
        });
    } else {
        res.status(404).json({
            error: 'Not Found',
            message: 'Пользователь с ID ' + id + ' не найден'
        });
    }
});

// ==================== ДОПОЛНИТЕЛЬНЫЕ МАРШРУТЫ ====================

/**
 * Функция 10: Статистика запросов
 * GET /api/stats
 */
app.get("/api/stats", auth.authMiddleware(), function(req, res) {
    var stats = rateLimiter.getStats(req.userId || req.ip);

    res.json({
        message: 'Статистика запросов',
        stats: stats,
        limits: rateLimiter.LIMITS[req.userRole] || rateLimiter.LIMITS.anonymous
    });
});

/**
 * Функция 11: Сброс лимитов (только для админов)
 * POST /api/stats/reset
 */
app.post("/api/stats/reset", auth.authMiddleware({ roles: ['admin'] }), jsonParser, function(req, res) {
    var userId = req.body.userId;

    if (!userId) {
        return res.status(400).json({
            error: 'Validation Error',
            message: 'Необходимо указать userId'
        });
    }

    rateLimiter.resetLimits(userId);

    res.json({
        message: 'Лимиты для пользователя ' + userId + ' сброшены'
    });
});

/**
 * Информация об API
 * GET /api
 */
app.get("/api", function(req, res) {
    res.json({
        name: 'REST API Service',
        version: '1.0.0',
        description: 'REST API сервис с авторизацией и лимитированием запросов',
        endpoints: {
            auth: {
                'POST /api/auth/register': 'Регистрация нового пользователя',
                'POST /api/auth/login': 'Авторизация',
                'GET /api/auth/profile': 'Профиль текущего пользователя',
                'GET /api/auth/users': 'Список пользователей (только админ)'
            },
            users: {
                'GET /api/users': 'Список пользователей (с пагинацией)',
                'GET /api/users/:id': 'Получить пользователя по ID',
                'GET /api/users/search?q=query': 'Поиск пользователей',
                'POST /api/users': 'Создать пользователя',
                'PUT /api/users/:id': 'Полное обновление пользователя',
                'PATCH /api/users/:id': 'Частичное обновление пользователя',
                'DELETE /api/users/:id': 'Удалить пользователя (только админ)'
            },
            stats: {
                'GET /api/stats': 'Статистика запросов',
                'POST /api/stats/reset': 'Сброс лимитов (только админ)'
            }
        },
        authentication: 'JWT Bearer Token в заголовке Authorization',
        rateLimiting: {
            anonymous: '10 запросов в минуту',
            user: '30 запросов в минуту',
            admin: '100 запросов в минуту'
        }
    });
});

/**
 * Главная страница - отдаём HTML-клиент
 * GET /
 */
app.get("/", function(req, res) {
    res.sendFile(path.join(__dirname, "API_app.html"));
});


// Обработка 404
app.use(function(req, res) {
    res.status(404).json({
        error: 'Not Found',
        message: 'Маршрут ' + req.method + ' ' + req.url + ' не найден'
    });
});

// Обработка ошибок
app.use(function(err, req, res, next) {
    console.error(err.stack);
    res.status(500).json({
        error: 'Internal Server Error',
        message: 'Произошла внутренняя ошибка сервера'
    });
});

// Запуск сервера
var PORT = process.env.PORT || 3000;
app.listen(PORT, function() {
    console.log('='.repeat(60));
    console.log('REST API Сервер запущен');
    console.log('Порт: ' + PORT);
    console.log('URL: http://localhost:' + PORT);
    console.log('API Docs: http://localhost:' + PORT + '/api');
    console.log('='.repeat(60));
    console.log('\nУчётные записи по умолчанию:');
    console.log('  Админ: admin / admin123');
    console.log('  Пользователь: user / user123');
    console.log('='.repeat(60));
});