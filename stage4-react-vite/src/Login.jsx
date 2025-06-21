import React, { useState } from 'react';
import { useAuth } from './AuthContext';

const Login = () => {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const { login } = useAuth();

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (!username || !password) {
            setError('Please enter both username and password');
            return;
        }

        setLoading(true);
        setError('');

        const result = await login(username, password);

        if (!result.success) {
            setError(result.error);
        }

        setLoading(false);
    };

    return (
        <div style={{
            minHeight: '100vh',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            backgroundColor: '#f0f0f0'
        }}>
            <div style={{
                backgroundColor: 'white',
                padding: '30px',
                borderRadius: '8px',
                boxShadow: '0 2px 10px rgba(0,0,0,0.1)',
                width: '300px'
            }}>
                <h2 style={{ textAlign: 'center', marginBottom: '20px' }}>Login</h2>

                {error && (
                    <div style={{
                        backgroundColor: '#ffebee',
                        color: '#c62828',
                        padding: '10px',
                        borderRadius: '4px',
                        marginBottom: '15px'
                    }}>
                        {error}
                    </div>
                )}

                <div style={{ marginBottom: '15px' }}>
                    <label>Username:</label>
                    <input
                        type="text"
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        style={{
                            width: '100%',
                            padding: '8px',
                            marginTop: '5px',
                            border: '1px solid #ddd',
                            borderRadius: '4px'
                        }}
                        onKeyPress={(e) => e.key === 'Enter' && handleSubmit(e)}
                    />
                </div>

                <div style={{ marginBottom: '20px' }}>
                    <label>Password:</label>
                    <input
                        type="password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        style={{
                            width: '100%',
                            padding: '8px',
                            marginTop: '5px',
                            border: '1px solid #ddd',
                            borderRadius: '4px'
                        }}
                        onKeyPress={(e) => e.key === 'Enter' && handleSubmit(e)}
                    />
                </div>

                <button
                    onClick={handleSubmit}
                    disabled={loading}
                    style={{
                        width: '100%',
                        padding: '10px',
                        backgroundColor: '#1976d2',
                        color: 'white',
                        border: 'none',
                        borderRadius: '4px',
                        cursor: loading ? 'not-allowed' : 'pointer',
                        opacity: loading ? 0.7 : 1
                    }}
                >
                    {loading ? 'Signing In...' : 'Sign In'}
                </button>
            </div>
        </div>
    );
};

export default Login;