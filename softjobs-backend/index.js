require('dotenv').config();

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');

// Obtener JWT_SECRET desde .env
const JWT_SECRET = process.env.JWT_SECRET || 'mi_clave_secreta_super_segura';

// Crear función para obtener JWT_SECRET
const getJWTSecret = () => JWT_SECRET;

// Importar funciones bd
const {
    registrarUsuario,
    verificarCredenciales,
    obtenerUsuario
} = require('./consultas');

// Importar middlewares
const {
    verificarCredencialesMiddleware,
    verificarTokenMiddleware,
    loggerMiddleware
} = require('./middlewares');

const app = express();
const PORT = process.env.PORT || 3000;

// Middlewares globales
app.use(cors());
app.use(express.json());
app.use(loggerMiddleware); // Middleware para reportar consultas

// RUTA: POST /usuarios - Registro de nuevos usuarios
app.post('/usuarios', verificarCredencialesMiddleware, async (req, res) => {
    try {
        const { email, password, rol, lenguage } = req.body;

        const nuevoUsuario = await registrarUsuario({
            email,
            password,
            rol,
            lenguage
        });

        res.status(201).json({
            message: "Usuario registrado con éxito",
            usuario: nuevoUsuario
        });
    } catch (error) {
        console.error('Error al registrar usuario:', error);

        // Manejar errores específicos - Frontend espera data.message
        if (error.message === 'El usuario ya existe') {
            return res.status(409).json({
                message: "El usuario ya existe"
            });
        }

        res.status(500).json({
            message: "Error interno del servidor"
        });
    }
});

// RUTA: POST /login - Autenticación de usuarios
app.post('/login', verificarCredencialesMiddleware, async (req, res) => {
    try {
        const { email, password } = req.body;

        const usuario = await verificarCredenciales(email, password);

        // Generar token JWT payload
        const payload = { email: usuario.email };
        const token = jwt.sign(payload, JWT_SECRET);

        res.json({
            message: "Inicio de sesión exitoso",
            token
        });
    } catch (error) {
        console.error('Error en login:', error);

        // Manejar errores específicos - Frontend espera data.message
        if (error.message === 'Usuario no encontrado' || error.message === 'Contraseña incorrecta') {
            return res.status(401).json({
                message: "Credenciales incorrectas"
            });
        }

        res.status(500).json({
            message: "Error interno del servidor"
        });
    }
});

// RUTA: GET /usuarios - Obtener datos usuario autenticado
app.get('/usuarios', verificarTokenMiddleware, async (req, res) => {
    try {
        // El email viene del middleware de verificación de token
        const email = req.email;

        const usuario = await obtenerUsuario(email);

        // Frontend espera un array [user] según Home.jsx y Profile.jsx
        res.json([{
            email: usuario.email,
            rol: usuario.rol,
            lenguage: usuario.lenguage
        }]);
    } catch (error) {
        console.error('Error al obtener usuario:', error);

        if (error.message === 'Usuario no encontrado') {
            return res.status(404).json({
                message: "Usuario no encontrado"
            });
        }

        res.status(500).json({
            message: "Error interno del servidor"
        });
    }
});

// Ruta de prueba para verificar que el servidor esté funcionando
app.get('/', (req, res) => {
    res.json({
        message: "Servidor Soft Jobs funcionando correctamente",
        endpoints: {
            registro: "POST /usuarios",
            login: "POST /login",
            perfil: "GET /usuarios"
        }
    });
});

// Middleware manejo rutas no encontradas
app.use('*', (req, res) => {
    res.status(404).json({
        message: "Ruta no encontrada"
    });
});

// Iniciar servidor
app.listen(PORT, () => {
    console.log(`🚀 Servidor Soft Jobs ejecutándose en http://localhost:${PORT}`);
    console.log(`📊 Endpoints disponibles:`);
    console.log(`   POST /usuarios - Registro de usuarios`);
    console.log(`   POST /login - Inicio de sesión`);
    console.log(`   GET /usuarios - Obtener perfil (requiere token)`);
});

module.exports = { getJWTSecret };