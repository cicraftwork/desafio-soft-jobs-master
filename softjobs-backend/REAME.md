Soft Jobs Backend
Sistema de autenticación y autorización con JWT para la plataforma Soft Jobs.

## Instalación

1.Clonar el repositorio:

bashgit clone https://github.com/cicraftwork/softjobs-backend.git
cd softjobs-backend

2.Instalar dependencias:

bashnpm install

3.Configurar variables de entorno:

bashcp .env.example .env

4.Editar el archivo .env con tus credenciales:


Cambiar JWT_SECRET por una clave única y segura
Configurar credenciales de PostgreSQL


5.Crear base de datos:

sqlCREATE DATABASE softjobs;
\c softjobs;
CREATE TABLE usuarios (
    id SERIAL,
    email VARCHAR(50) NOT NULL,
    password VARCHAR(60) NOT NULL,
    rol VARCHAR(25),
    lenguage VARCHAR(20)
);

6.Iniciar servidor:

bash
Desarrollo

npm run dev
