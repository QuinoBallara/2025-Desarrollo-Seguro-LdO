import React, { useState, useEffect } from 'react';
import { Navigate } from 'react-router-dom';
import api from '../api';

export default function ProtectedRoute({ children }) {
  const [isValidToken, setIsValidToken] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  
  useEffect(() => {
    const validateToken = async () => {
      const token = localStorage.getItem('token');
      
      if (!token) {
        setIsValidToken(false);
        setIsLoading(false);
        return;
      }
      
      try {
        const response = await api.get('/auth/validate-token', {
          headers: {
            Authorization: `Bearer ${token}`
          }
        });
        
        if (response.data.valid) {
          setIsValidToken(true);
        } else {
          setIsValidToken(false);
          localStorage.removeItem('token'); 
        }
      } catch (error) {
        setIsValidToken(false);
        localStorage.removeItem('token'); 
      }
      
      setIsLoading(false);
    };
    
    validateToken();
  }, []);
  
  if (isLoading) {
    return <div>Loading...</div>;
  }
  
  return isValidToken ? children : <Navigate to="/login" replace />;
}
