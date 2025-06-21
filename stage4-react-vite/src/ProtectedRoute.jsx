import React from 'react';
import { useAuth } from './AuthContext';
import Login from './Login';

const ProtectedRoute = ({ children }) => {
    const { user, loading } = useAuth();

    if (loading) {
        return (
            <div style={{ padding: '50px', textAlign: 'center' }}>
                <div>Loading...</div>
            </div>
        );
    }

    if (!user) {
        return <Login />;
    }

    return children;
};

export default ProtectedRoute;