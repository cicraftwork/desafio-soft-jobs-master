const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

// Configuración de la conexión a PostgreSQL usando variables de entorno
const pool = new Pool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD || 'password',
    database: process.env.DB_NAME || 'softjobs',
    port: process.env.DB_PORT || 5432,
    allowExitOnIdle: true
});

// Función para registrar un nuevo usuario
const registrarUsuario = async ({ email, password, rol, lenguage }) => {
    try {
        // Verificar si el usuario ya existe
        const consultaExistencia = 'SELECT * FROM usuarios WHERE email = $1';
        const { rows: usuarioExistente } = await pool.query(consultaExistencia, [email]);

        if (usuarioExistente.length > 0) {
            throw new Error('El usuario ya existe');
        }

        // Encriptar la contraseña
        const passwordEncriptada = await bcrypt.hash(password, 10);

        // Insertar nuevo usuario
        const consulta = `
            INSERT INTO usuarios (email, password, rol, lenguage)
            VALUES ($1, $2, $3, $4)
            RETURNING id, email, rol, lenguage
        `;
        const valores = [email, passwordEncriptada, rol, lenguage];

        const { rows } = await pool.query(consulta, valores);

        console.log('Usuario registrado:', rows[0]);
        return rows[0];
    } catch (error) {
        console.error('Error en registrarUsuario:', error.message);
        throw error;
    }
};

// Función para verificar credenciales de login
const verificarCredenciales = async (email, password) => {
    try {
        const consulta = 'SELECT * FROM usuarios WHERE email = $1';
        const { rows } = await pool.query(consulta, [email]);

        if (rows.length === 0) {
            throw new Error('Usuario no encontrado');
        }

        const usuario = rows[0];

        // Verificar contraseña
        const passwordValida = await bcrypt.compare(password, usuario.password);

        if (!passwordValida) {
            throw new Error('Contraseña incorrecta');
        }

        console.log('Credenciales verificadas para:', email);
        return usuario;
    } catch (error) {
        console.error('Error en verificarCredenciales:', error.message);
        throw error;
    }
};

// Función para obtener datos de un usuario por email
const obtenerUsuario = async (email) => {
    try {
        const consulta = 'SELECT id, email, rol, lenguage FROM usuarios WHERE email = $1';
        const { rows } = await pool.query(consulta, [email]);

        if (rows.length === 0) {
            throw new Error('Usuario no encontrado');
        }

        console.log('Usuario obtenido:', rows[0]);
        return rows[0];
    } catch (error) {
        console.error('Error en obtenerUsuario:', error.message);
        throw error;
    }
};

module.exports = {
    registrarUsuario,
    verificarCredenciales,
    obtenerUsuario
};