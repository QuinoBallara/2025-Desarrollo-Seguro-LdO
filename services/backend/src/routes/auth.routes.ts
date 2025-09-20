import { Router } from 'express';
import routes from '../controllers/authController';
import authenticateJWT from '../middleware/auth.middleware';

const router = Router();

router.get('/', routes.ping);

router.post('/login', routes.login);

// POST /auth/forgot-password
router.post('/forgot-password', routes.forgotPassword);

// POST /auth/reset-password
router.post('/reset-password', routes.resetPassword);

// POST /auth/set-password
router.post('/set-password', routes.setPassword);

// GET /auth/validate-token - protected by auth middleware
router.get('/validate-token', authenticateJWT, routes.validateToken);

export default router;
