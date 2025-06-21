import React, { createContext, useContext, useState, useEffect } from 'react';

// Simple JWT decode function
const jwtDecode = (token) => {
    try {
        const base64Url = token.split('.')[1];
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));
        return JSON.parse(jsonPayload);
        // eslint-disable-next-line no-unused-vars
    } catch (error) {
        throw new Error('Invalid token');
    }
};

// Auth Context
const AuthContext = createContext();

// Auth Provider
export const AuthProvider = ({ children }) => {
    const [user, setUser] = useState(null);
    const [accessToken, setAccessToken] = useState(null);
    const [refreshToken, setRefreshToken] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const storedAccessToken = sessionStorage.getItem('accessToken');
        const storedRefreshToken = sessionStorage.getItem('refreshToken');

        if (storedAccessToken && storedRefreshToken) {
            try {
                const decodedToken = jwtDecode(storedAccessToken);

                // בדוק אם הטוקן עדיין תקף
                if (decodedToken.exp * 1000 > Date.now()) {
                    setAccessToken(storedAccessToken);
                    setRefreshToken(storedRefreshToken);
                    setUser(decodedToken);
                    console.log('Loaded valid token from storage');
                } else {
                    console.log('Stored token expired, clearing storage');
                    sessionStorage.removeItem('accessToken');
                    sessionStorage.removeItem('refreshToken');
                }
            } catch (error) {
                console.error('Invalid stored token:', error);
                sessionStorage.removeItem('accessToken');
                sessionStorage.removeItem('refreshToken');
            }
        }
        setLoading(false);
    }, []); // רק פעם אחת בטעינה

    const login = async (username, password) => {
        console.log('Login attempt for username:', username);

        if (!username || !password) {
            console.error('Username or password missing');
            return { success: false, error: 'Username and password are required' };
        }

        try {
            const loginData = { username, password };
            console.log('Sending login request with data:', { username, password: '***' });

            const response = await fetch('http://localhost:8080/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(loginData),
            });

            console.log('Login response status:', response.status);

            if (response.ok) {
                const data = await response.json();
                console.log('Login successful, received tokens');

                const decodedToken = jwtDecode(data.accessToken);

                sessionStorage.setItem('accessToken', data.accessToken);
                sessionStorage.setItem('refreshToken', data.refreshToken);

                setAccessToken(data.accessToken);
                setRefreshToken(data.refreshToken);
                setUser(decodedToken);

                console.log('User set:', decodedToken.sub);
                return { success: true };
            } else {
                const error = await response.text();
                console.error('Login failed:', error);
                return { success: false, error };
            }
        } catch (error) {
            console.error('Login network error:', error);
            return { success: false, error: 'Network error occurred' };
        }
    };

    const handleRefreshToken = async (refreshTokenToUse = refreshToken) => {
        try {
            console.log('Calling refresh token endpoint with token:', refreshTokenToUse ? 'Token exists' : 'No token');

            const response = await fetch('http://localhost:8080/api/refresh_token', {  // תיקון: ודא שזה refresh_token לא login
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ refreshToken: refreshTokenToUse }),
            });

            console.log('Refresh response status:', response.status);

            if (response.ok) {
                const data = await response.json();
                const decodedToken = jwtDecode(data.accessToken);

                sessionStorage.setItem('accessToken', data.accessToken);
                sessionStorage.setItem('refreshToken', data.refreshToken);

                setAccessToken(data.accessToken);
                setRefreshToken(data.refreshToken);
                setUser(decodedToken);

                console.log('Token refresh successful');
                return data.accessToken;
            } else {
                const errorText = await response.text();
                console.error('Refresh failed with status:', response.status, 'Error:', errorText);
                logout();
                return null;
            }
        } catch (error) {
            console.error('Refresh token error:', error);
            logout();
            return null;
        }
    };

    const logout = async () => {
        try {
            if (accessToken) {
                await fetch('http://localhost:8080/api/logout', {
                    method: 'POST',
                    headers: { 'Authorization': `Bearer ${accessToken}` },
                });
            }
        } catch (error) {
            console.error('Logout error:', error);
        }

        sessionStorage.removeItem('accessToken');
        sessionStorage.removeItem('refreshToken');

        setAccessToken(null);
        setRefreshToken(null);
        setUser(null);
    };

    // API Wrapper - checks token before each request
    const authenticatedFetch = async (url, options = {}) => {
        console.log('authenticatedFetch called for:', url);

        if (!accessToken || !user) {
            console.log('No access token or user, redirecting to login');
            logout();
            throw new Error('No authentication data');
        }

        const tokenExp = user.exp * 1000;
        const currentTime = Date.now();
        const timeUntilExpiry = tokenExp - currentTime;

        console.log(`Token expires in: ${Math.floor(timeUntilExpiry / 1000)} seconds`);

        // אם הטוקן עומד לפוג תוקף בפחות מ-2 דקות
        if (timeUntilExpiry < 120000 && timeUntilExpiry > 0) { // 2 minutes
            console.log('Token about to expire, attempting refresh...');

            if (!refreshToken) {
                console.log('No refresh token available');
                logout();
                throw new Error('No refresh token available');
            }

            try {
                // בדוק שגם הRefresh token לא פג
                const refreshDecoded = jwtDecode(refreshToken);
                if (refreshDecoded.exp * 1000 <= Date.now()) {
                    console.log('Refresh token expired, logging out...');
                    logout();
                    throw new Error('Refresh token expired');
                }

                const newAccessToken = await handleRefreshToken(refreshToken);
                if (!newAccessToken) {
                    console.log('Token refresh failed');
                    throw new Error('Token refresh failed');
                }

                // השתמש בטוקן החדש לבקשה הזו
                options.headers = {
                    ...options.headers,
                    'Authorization': `Bearer ${newAccessToken}`,
                };
            } catch (refreshError) {
                console.error('Refresh error:', refreshError);
                logout();
                throw new Error('Session expired');
            }
        } else if (timeUntilExpiry <= 0) {
            console.log('Token already expired');
            logout();
            throw new Error('Token expired');
        } else {
            // השתמש בטוקן הנוכחי
            options.headers = {
                ...options.headers,
                'Authorization': `Bearer ${accessToken}`,
            };
        }

        console.log('Making authenticated request to:', url);
        return fetch(url, options);
    };

    const value = {
        user,
        accessToken,
        refreshToken,
        login,
        logout,
        loading,
        authenticatedFetch,
    };

    return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

// Hook to use auth context
export const useAuth = () => {
    const context = useContext(AuthContext);
    if (!context) {
        throw new Error('useAuth must be used within an AuthProvider');
    }
    return context;
};