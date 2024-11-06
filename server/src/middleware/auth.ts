import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

interface JwtPayload {
  username: string;
}

export const authenticateToken = (req: Request, res: Response, next: NextFunction) => {
  // Get the token from the Authorization header or other source
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; 

  if (!token) {
    // If no token is provided, return 401 Unauthorized
    return res.status(401).json({ message: 'Access denied. No token provided.' });
  }

  try {
    // Verify the token
    const secret = process.env.JWT_SECRET_KEY || 'your_jwt_secret'; // Make sure the secret is stored securely
    const decoded = jwt.verify(token, secret) as JwtPayload;

    // Attach the decoded token data (e.g., username) to the request object
    req.user = decoded; // Assuming you want to store user info in req.user

    // Call next to proceed to the next middleware
    return next();
  } catch (error) {
    // If token is invalid, return 403 Forbidden
    return res.status(403).json({ message: 'Invalid token.' });
  }
};
