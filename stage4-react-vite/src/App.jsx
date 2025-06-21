import React from 'react';
import { AuthProvider } from './AuthContext';
import ProtectedRoute from './ProtectedRoute';
import Home from './Home';

const App = () => {
    return (
        <AuthProvider>
            <ProtectedRoute>
                <Home />
            </ProtectedRoute>
        </AuthProvider>
    );
};

export default App;