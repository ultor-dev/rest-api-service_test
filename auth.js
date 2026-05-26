/**
 * Модуль авторизации клиентов
 * Использует JWT токены для аутентификации
 */

const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

// Секретный ключ для JWT (в продакшене должен быть в переменных окружения)
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const JWT_EXPIRES_IN = '24h';

// Файл для хранения пользователей аутентификации
const AUTH_USERS_FILE = 'auth_users.json';

/**
 * Загрузка пользователей аутентификации из файла
 * @returns {Array} массив пользователей
 */
function loadAuthUsers() {
    try {
        const data = fs.readFileSync(AUTH_USERS_FILE, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        // Если файл не существует, создаём администратора по умолчанию
        const defaultUsers = [
            {
                id: '1',
                username: 'admin',
                password: bcrypt.hashSync('admin123', 10),
                role: 'admin',
                email: 'admin@example.com',
                createdAt: new Date().toISOString(),
                isActive: true
            },
            {
                id: '2',
                username: 'user',
                password: bcrypt.hashSync('user123', 10),
                role: 'user',
                email: 'user@example.com',
                createdAt: new Date().toISOString(),
                isActive: true
            }
        ];
        saveAuthUsers(defaultUsers);
        return defaultUsers;
    }
}

/**
 * Сохранение пользователей аутентификации в файл
 * @param {Array} users - массив пользователей
 */
function saveAuthUsers(users) {
    fs.writeFileSync(AUTH_USERS_FILE, JSON.stringify(users, null, 2));
}

/**
 * Регистрация нового пользователя
 * @param {Object} userData - данные пользователя
 * @returns {Object} результат регистрации
 */
function register(userData) {
    const users = loadAuthUsers();

    // Проверяем, существует ли пользователь
    if (users.find(u => u.username === userData.username)) {
        return { success: false, message: 'Пользователь с таким именем уже существует' };
    }

    if (users.find(u => u.email === userData.email)) {
        return { success: false, message: 'Пользователь с таким email уже существует' };
    }

    // Создаём нового пользователя
    const newUser = {
        id: uuidv4(),
        username: userData.username,
        password: bcrypt.hashSync(userData.password, 10),
        role: userData.role || 'user',
        email: userData.email,
        createdAt: new Date().toISOString(),
        isActive: true
    };

    users.push(newUser);
    saveAuthUsers(users);

    // Не возвращаем пароль
    const { password, ...userWithoutPassword } = newUser;
    return { success: true, user: userWithoutPassword };
}

/**
 * Аутентификация пользователя
 * @param {string} username - имя пользователя
 * @param {string} password - пароль
 * @returns {Object} результат аутентификации с токеном
 */
function login(username, password) {
    const users = loadAuthUsers();
    const user = users.find(u => u.username === username);

    if (!user) {
        return { success: false, message: 'Неверное имя пользователя или пароль' };
    }

    if (!user.isActive) {
        return { success: false, message: 'Аккаунт деактивирован' };
    }

    if (!bcrypt.compareSync(password, user.password)) {
        return { success: false, message: 'Неверное имя пользователя или пароль' };
    }

    // Генерируем JWT токен
    const token = jwt.sign(
        {
            userId: user.id,
            username: user.username,
            role: user.role
        },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES_IN }
    );

    const { password: _, ...userWithoutPassword } = user;

    return {
        success: true,
        token: token,
        user: userWithoutPassword,
        expiresIn: JWT_EXPIRES_IN
    };
}

/**
 * Верификация JWT токена
 * @param {string} token - JWT токен
 * @returns {Object} декодированные данные токена
 */
function verifyToken(token) {
    try {
        return { success: true, decoded: jwt.verify(token, JWT_SECRET) };
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return { success: false, message: 'Токен истёк' };
        }
        return { success: false, message: 'Недействительный токен' };
    }
}

/**
 * Middleware для проверки авторизации
 * @param {Object} options - настройки
 * @param {Array} options.roles - допустимые роли (по умолчанию все)
 * @returns {Function} Express middleware
 */
function authMiddleware(options = {}) {
    const allowedRoles = options.roles || ['admin', 'user'];

    return function(req, res, next) {
        // Получаем токен из заголовка
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

        if (!token) {
            return res.status(401).json({
                error: 'Unauthorized',
                message: 'Токен авторизации не предоставлен. Используйте заголовок Authorization: Bearer <token>'
            });
        }

        const result = verifyToken(token);

        if (!result.success) {
            return res.status(401).json({
                error: 'Unauthorized',
                message: result.message
            });
        }

        // Проверяем роль
        if (!allowedRoles.includes(result.decoded.role)) {
            return res.status(403).json({
                error: 'Forbidden',
                message: 'Недостаточно прав для выполнения этой операции'
            });
        }

        // Добавляем информацию о пользователе в запрос
        req.userId = result.decoded.userId;
        req.username = result.decoded.username;
        req.userRole = result.decoded.role;

        next();
    };
}

/**
 * Получение списка пользователей аутентификации (только для админов)
 * @returns {Array} список пользователей без паролей
 */
function getAuthUsers() {
    const users = loadAuthUsers();
    return users.map(({ password, ...user }) => user);
}

/**
 * Обновление данных пользователя аутентификации
 * @param {string} userId - ID пользователя
 * @param {Object} updates - обновляемые данные
 * @returns {Object} результат обновления
 */
function updateAuthUser(userId, updates) {
    const users = loadAuthUsers();
    const index = users.findIndex(u => u.id === userId);

    if (index === -1) {
        return { success: false, message: 'Пользователь не найден' };
    }

    // Обновляем разрешённые поля
    const allowedFields = ['username', 'email', 'role', 'isActive'];
    for (const field of allowedFields) {
        if (updates[field] !== undefined) {
            users[index][field] = updates[field];
        }
    }

    // Если обновляется пароль
    if (updates.password) {
        users[index].password = bcrypt.hashSync(updates.password, 10);
    }

    users[index].updatedAt = new Date().toISOString();
    saveAuthUsers(users);

    const { password, ...userWithoutPassword } = users[index];
    return { success: true, user: userWithoutPassword };
}

/**
 * Удаление пользователя аутентификации
 * @param {string} userId - ID пользователя
 * @returns {Object} результат удаления
 */
function deleteAuthUser(userId) {
    const users = loadAuthUsers();
    const index = users.findIndex(u => u.id === userId);

    if (index === -1) {
        return { success: false, message: 'Пользователь не найден' };
    }

    const deleted = users.splice(index, 1)[0];
    saveAuthUsers(users);

    const { password, ...userWithoutPassword } = deleted;
    return { success: true, user: userWithoutPassword };
}

module.exports = {
    register,
    login,
    verifyToken,
    authMiddleware,
    getAuthUsers,
    updateAuthUser,
    deleteAuthUser,
    loadAuthUsers,
    saveAuthUsers
};