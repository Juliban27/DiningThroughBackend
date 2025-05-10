import dotenv from 'dotenv';
dotenv.config();

export const PORT          = process.env.PORT;
export const DB_URI        = process.env.DB_URI;
export const JWT_SECRET    = process.env.JWT_SECRET;
export const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN;
export const SALT_ROUNDS   = parseInt(process.env.SALT_ROUNDS, 10);
