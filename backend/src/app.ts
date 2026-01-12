import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import cors from 'cors';

import scanRouter from './routes/scan.route';

const app = express();

app.use(cors());
app.use(express.json());

app.get('/health', (_, res) => {
  res.json({ status: 'ok' });
});

app.use('/api/scan', scanRouter);

export default app;
console.log("PORT:", process.env.PORT);
