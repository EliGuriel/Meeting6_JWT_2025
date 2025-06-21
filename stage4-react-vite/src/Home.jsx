import React, { useState, useEffect } from 'react';
import { useAuth } from './AuthContext';
import TokenDisplay from './TokenDisplay';

const Home = () => {
    const { user, accessToken, refreshToken, logout, authenticatedFetch } = useAuth();
    const [protectedMessage, setProtectedMessage] = useState('');

    useEffect(() => {
        const fetchProtectedMessage = async () => {
            try {
                const response = await authenticatedFetch('/api/protected-message');

                if (response.ok) {
                    const message = await response.text();
                    setProtectedMessage(message);
                }
            } catch (error) {
                console.error('Error fetching protected message:', error);
            }
        };

        if (accessToken) {
            fetchProtectedMessage();
        }
    }, [accessToken, authenticatedFetch]);

    const isAdmin = user?.roles?.includes('ROLE_ADMIN');

    return (
        <div style={{ minHeight: '100vh', backgroundColor: '#f5f5f5' }}>
            {/* Navigation */}
            <nav style={{ backgroundColor: 'white', padding: '15px', boxShadow: '0 2px 4px rgba(0,0,0,0.1)' }}>
                <div style={{
                    maxWidth: '1200px',
                    margin: '0 auto',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center'
                }}>
                    <h1 style={{ margin: 0 }}>Dashboard</h1>
                    <div>
                        <button
                            onClick={() => window.location.reload()}
                            style={{
                                marginRight: '10px',
                                padding: '8px 15px',
                                backgroundColor: '#1976d2',
                                color: 'white',
                                border: 'none',
                                borderRadius: '4px',
                                cursor: 'pointer'
                            }}
                        >
                            Refresh
                        </button>
                        <button
                            onClick={logout}
                            style={{
                                padding: '8px 15px',
                                backgroundColor: '#d32f2f',
                                color: 'white',
                                border: 'none',
                                borderRadius: '4px',
                                cursor: 'pointer'
                            }}
                        >
                            Logout
                        </button>
                    </div>
                </div>
            </nav>

            {/* Content */}
            <div style={{ maxWidth: '1200px', margin: '0 auto', padding: '20px' }}>
                <div style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
                    gap: '20px'
                }}>

                    {/* User Information */}
                    <div style={{
                        backgroundColor: 'white',
                        padding: '20px',
                        borderRadius: '8px',
                        boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
                    }}>
                        <h2>User Information</h2>

                        <div style={{ marginBottom: '15px' }}>
                            <strong>Username:</strong> {user?.sub}
                        </div>

                        <div style={{ marginBottom: '15px' }}>
                            <strong>Roles:</strong>
                            <div>
                                {user?.roles?.map((role, index) => (
                                    <span
                                        key={index}
                                        style={{
                                            display: 'inline-block',
                                            padding: '3px 8px',
                                            margin: '2px',
                                            backgroundColor: role === 'ROLE_ADMIN' ? '#ffcdd2' : '#e3f2fd',
                                            color: role === 'ROLE_ADMIN' ? '#d32f2f' : '#1976d2',
                                            borderRadius: '12px',
                                            fontSize: '12px'
                                        }}
                                    >
                    {role.replace('ROLE_', '')}
                  </span>
                                ))}
                            </div>
                        </div>

                        <div style={{ marginBottom: '15px' }}>
                            <strong>IP Address:</strong> {user?.ipAddress}
                        </div>

                        <div style={{ marginBottom: '15px' }}>
                            <strong>Token Issued By:</strong> {user?.issuedBy}
                        </div>

                        {protectedMessage && (
                            <div style={{
                                marginTop: '15px',
                                padding: '10px',
                                backgroundColor: '#e8f5e8',
                                border: '1px solid #4caf50',
                                borderRadius: '4px',
                                color: '#2e7d32'
                            }}>
                                {protectedMessage}
                            </div>
                        )}
                    </div>

                    {/* Admin Panel */}
                    {isAdmin && (
                        <div style={{
                            backgroundColor: 'white',
                            padding: '20px',
                            borderRadius: '8px',
                            boxShadow: '0 2px 4px rgba(0,0,0,0.1)',
                            borderLeft: '4px solid #d32f2f'
                        }}>
                            <h2 style={{ color: '#d32f2f' }}>Admin Panel</h2>

                            <div style={{
                                backgroundColor: '#ffebee',
                                padding: '15px',
                                borderRadius: '4px',
                                marginBottom: '15px',
                                border: '1px solid #ffcdd2'
                            }}>
                                <h3 style={{ margin: '0 0 10px 0', color: '#d32f2f' }}>Admin Access Granted</h3>
                                <p style={{ margin: 0, color: '#c62828' }}>
                                    You have administrative privileges. You can access sensitive system information and perform admin operations.
                                </p>
                            </div>

                            <div style={{
                                backgroundColor: '#e3f2fd',
                                padding: '15px',
                                borderRadius: '4px',
                                border: '1px solid #bbdefb'
                            }}>
                                <h3 style={{ margin: '0 0 10px 0', color: '#1976d2' }}>System Status</h3>
                                <ul style={{ margin: 0, paddingLeft: '20px', color: '#1565c0' }}>
                                    <li>JWT Authentication: Active</li>
                                    <li>IP Validation: Enabled</li>
                                    <li>Token Blacklist: Operational</li>
                                    <li>Session Management: Stateless</li>
                                    <li>Activity-Based Token Refresh: Active</li>
                                    <li>Token Times: Display on Page Refresh Only</li>
                                </ul>
                            </div>
                        </div>
                    )}
                </div>

                {/* Token Information */}
                <div style={{
                    backgroundColor: 'white',
                    padding: '20px',
                    borderRadius: '8px',
                    boxShadow: '0 2px 4px rgba(0,0,0,0.1)',
                    marginTop: '20px'
                }}>
                    <h2>Token Information</h2>
                    <div style={{
                        backgroundColor: '#e3f2fd',
                        padding: '10px',
                        borderRadius: '4px',
                        marginBottom: '15px',
                        border: '1px solid #bbdefb'
                    }}>
                        <strong>Note:</strong> Token times are displayed at page load and refresh only.
                        Tokens are automatically refreshed during API activity when needed.
                    </div>

                    <div style={{
                        display: 'grid',
                        gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
                        gap: '15px'
                    }}>
                        <TokenDisplay token={accessToken} label="Access Token" />
                        <TokenDisplay token={refreshToken} label="Refresh Token" />
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Home;