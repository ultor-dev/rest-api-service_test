/**
 * Модуль ограничения количества запросов от одного пользователя
 * Использует скользящее окно (sliding window) для подсчёта запросов
 */

// Хранилище запросов: Map<userId, Array<timestamp>>
const requestStore = new Map();

// Настройки лимитов
const LIMITS = {
    // Максимум запросов в минуту для обычных пользователей
    user: {
        maxRequests: 30,
        windowMs: 60 * 1000 // 1 минута
    },
    // Максимум запросов в минуту для администраторов
    admin: {
        maxRequests: 100,
        windowMs: 60 * 1000 // 1 минута
    },
    // Максимум запросов в минуту для неавторизованных
    anonymous: {
        maxRequests: 10,
        windowMs: 60 * 1000 // 1 минута
    }
};

/**
 * Очистка устаревших записей из хранилища
 * Вызывается периодически для предотвращения утечки памяти
 */
function cleanup() {
    const now = Date.now();
    for (const [userId, timestamps] of requestStore.entries()) {
        // Удаляем записи старше 2 минут
        const filtered = timestamps.filter(t => now - t < 2 * 60 * 1000);
        if (filtered.length === 0) {
            requestStore.delete(userId);
        } else {
            requestStore.set(userId, filtered);
        }
    }
}

// Запускаем очистку каждые 5 минут
setInterval(cleanup, 5 * 60 * 1000);

/**
 * Middleware для ограничения запросов
 * @param {Object} options - настройки
 * @param {Function} options.getUserId - функция для получения ID пользователя из запроса
 * @returns {Function} Express middleware
 */
function rateLimiter(options = {}) {
    const getUserId = options.getUserId || (req => req.userId || req.ip);

    return function(req, res, next) {
        const userId = getUserId(req);
        const userRole = req.userRole || 'anonymous';
        const limit = LIMITS[userRole] || LIMITS.anonymous;
        const now = Date.now();

        // Получаем историю запросов пользователя
        if (!requestStore.has(userId)) {
            requestStore.set(userId, []);
        }

        const timestamps = requestStore.get(userId);

        // Удаляем запросы за пределами окна
        const windowStart = now - limit.windowMs;
        const recentRequests = timestamps.filter(t => t > windowStart);

        // Проверяем лимит
        if (recentRequests.length >= limit.maxRequests) {
            const retryAfter = Math.ceil((recentRequests[0] + limit.windowMs - now) / 1000);

            res.set({
                'X-RateLimit-Limit': limit.maxRequests,
                'X-RateLimit-Remaining': 0,
                'X-RateLimit-Reset': new Date(recentRequests[0] + limit.windowMs).toISOString(),
                'Retry-After': retryAfter
            });

            return res.status(429).json({
                error: 'Too Many Requests',
                message: `Превышен лимит запросов. Попробуйте снова через ${retryAfter} секунд.`,
                limit: limit.maxRequests,
                window: `${limit.windowMs / 1000} секунд`,
                retryAfter: retryAfter
            });
        }

        // Добавляем текущий запрос
        recentRequests.push(now);
        requestStore.set(userId, recentRequests);

        // Устанавливаем заголовки с информацией о лимитах
        res.set({
            'X-RateLimit-Limit': limit.maxRequests,
            'X-RateLimit-Remaining': limit.maxRequests - recentRequests.length,
            'X-RateLimit-Reset': new Date(now + limit.windowMs).toISOString()
        });

        next();
    };
}

/**
 * Получение статистики запросов для пользователя
 * @param {string} userId - ID пользователя
 * @returns {Object} статистика
 */
function getStats(userId) {
    const timestamps = requestStore.get(userId) || [];
    const now = Date.now();
    const recentRequests = timestamps.filter(t => now - t < 60 * 1000);

    return {
        totalRequests: timestamps.length,
        requestsLastMinute: recentRequests.length,
        firstRequest: timestamps.length > 0 ? new Date(timestamps[0]).toISOString() : null,
        lastRequest: timestamps.length > 0 ? new Date(timestamps[timestamps.length - 1]).toISOString() : null
    };
}

/**
 * Сброс лимитов для пользователя (для администрирования)
 * @param {string} userId - ID пользователя
 */
function resetLimits(userId) {
    requestStore.delete(userId);
}

module.exports = {
    rateLimiter,
    getStats,
    resetLimits,
    LIMITS
};