const jwt = require('jsonwebtoken');

// Obtener JWT_SECRET desde variables de entorno
const JWT_SECRET = process.env.JWT_SECRET || 'mi_clave_secreta_super_segura';

// Middleware para verificar existencia de credenciales
const verificarCredencialesMiddleware = (req, res, next) => {
    const { email, password } = req.body;

    // Verificar que se enviaron las credenciales
    if (!email || !password) {
        return res.status(400).json({
            message: "Email y contraseña son requeridos"
        });
    }

    // Verificar que no estén vacías
    if (email.trim() === '' || password.trim() === '') {
        return res.status(400).json({
            message: "Email y contraseña no pueden estar vacíos"
        });
    }

    // Validación básica formato de email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({
            message: "Formato de email inválido"
        });
    }

    console.log('✓ Credenciales verificadas para:', email);
    next();
};

// Middleware para verificar y decodificar token JWT
const verificarTokenMiddleware = (req, res, next) => {
    try {
        // Obtener token del header Authorization
        const authorization = req.headers.authorization;

        if (!authorization) {
            return res.status(401).json({
                message: "Token de acceso requerido"
            });
        }

        // Extraer el token (formato: "Bearer token" o solo "token")
        const token = authorization.startsWith('Bearer ')
            ? authorization.split(' ')[1]
            : authorization;

        if (!token) {
            return res.status(401).json({
                message: "Formato de token inválido"
            });
        }

        // Verificar y decodificar el token
        const payload = jwt.verify(token, JWT_SECRET);

        // Verificar que el payload tenga el email
        if (!payload.email) {
            return res.status(401).json({
                message: "Token inválido: no contiene email"
            });
        }

        // Agregar email al request para usarlo en la ruta
        req.email = payload.email;

        console.log('✓ Token verificado para usuario:', payload.email);
        next();
    } catch (error) {
        console.error('Error en verificación de token:', error.message);

        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({
                message: "Token inválido o malformado"
            });
        }

        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({
                message: "Token expirado. Inicie sesión nuevamente"
            });
        }

        if (error.name === 'NotBeforeError') {
            return res.status(401).json({
                message: "Token no válido aún"
            });
        }

        return res.status(500).json({
            message: "Error interno al verificar token"
        });
    }
};

// Middleware consultas en la terminal
const loggerMiddleware = (req, res, next) => {
    const timestamp = new Date().toISOString();
    const method = req.method;
    const url = req.originalUrl;
    const ip = req.ip || req.connection.remoteAddress || 'unknown';

    // Log con colores para mejor visualización
    console.log(`\n📝 [${timestamp}] ${method} ${url}`);
    console.log(`🌐 IP: ${ip}`);

    // Log del body si es POST (sin mostrar passwords)
    if (method === 'POST' && req.body) {
        const bodyLog = { ...req.body };
        if (bodyLog.password) {
            bodyLog.password = '*'.repeat(bodyLog.password.length);
        }
        console.log(`📦 Body:`, bodyLog);
    }

    // Log de headers de autorización (sin mostrar el token completo)
    if (req.headers.authorization) {
        const token = req.headers.authorization.startsWith('Bearer ')
            ? req.headers.authorization.split(' ')[1]
            : req.headers.authorization;
        console.log(`🔑 Token presente: ${token.substring(0, 20)}...`);
    }

    console.log('─'.repeat(50));
    next();
};

module.exports = {
    verificarCredencialesMiddleware,
    verificarTokenMiddleware,
    loggerMiddleware
};