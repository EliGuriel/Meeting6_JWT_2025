

<div dir="rtl">

# מערכת אימות JWT מתקדמת - React Frontend ניתוח מקיף

## רעיון האפליקציה

זוהי אפליקציית React מתקדמת לניהול אימות עם Spring Boot backend. האפליקציה מדגימה:
- **Context API מתקדם** לניהול מצב גלובלי
- **Higher-Order Components (HOC)** לעטיפת קומפוננטות
- **Custom Hooks** לשימוש חוזר בלוגיקה
- **JWT Token Management** אוטומטי עם רענון
- **Conditional Rendering** מבוסס הרשאות

## ארכיטקטורה React - מבנה היררכי

</div>

```mermaid
graph TB
    subgraph "React App Structure"
        A[main.jsx - Entry Point] --> B[App.jsx]
        B --> C[AuthProvider]
        C --> D[ProtectedRoute]
        D --> E[Home Component]
        
        F[Login Component] --> C
        G[TokenDisplay Component] --> E
    end
    
    subgraph "Context & State Management"
        H[AuthContext] --> I[useState hooks]
        H --> J[useEffect hooks]
        H --> K[Custom functions]
        
        I --> I1[user state]
        I --> I2[accessToken state]
        I --> I3[refreshToken state]
        I --> I4[loading state]
        
        K --> K1[login function]
        K --> K2[logout function]
        K --> K3[authenticatedFetch]
        K --> K4[handleRefreshToken]
    end
    
    subgraph "Browser APIs"
        L[sessionStorage] --> M[Token Persistence]
        N[fetch API] --> O[HTTP Requests]
        P[atob/btoa] --> Q[JWT Decoding]
    end
    
    C --> H
    E --> L
    K3 --> N
    K4 --> P
```

<div dir="rtl">

## מושג Children ב-React - הסבר מקיף

### מהו Children ולמה זה חשוב?

ב-React, `children` הוא **special prop** שמאפשר **Component Composition**. זה אחד מהעקרונות הבסיסיים של React המאפשר גמישות ושימוש חוזר.

### דוגמה בסיסית עם הסבר מפורט:

</div>

```jsx
// Container Component that accepts children
function Wrapper({ children, title, className }) {
    return (
        <div className={`wrapper ${className}`}>
            <header>
                <h1>{title}</h1>
            </header>
            <main className="content">
                {children}  {/* React "injects" the passed content here */}
            </main>
            <footer>
                <p>© 2024 My App</p>
            </footer>
        </div>
    );
}

// Usage - everything inside the tags becomes children
<Wrapper title="דף בית" className="main-wrapper">
    <p>זה התוכן שיוצג ב-children</p>
    <button onClick={() => alert('לחצתי!')}>כפתור</button>
    <ul>
        <li>פריט 1</li>
        <li>פריט 2</li>
    </ul>
</Wrapper>

// What React sees "behind the scenes":
React.createElement(Wrapper, {
    title: "דף בית",
    className: "main-wrapper",
    children: [
        React.createElement('p', {}, 'זה התוכן שיוצג ב-children'),
        React.createElement('button', { 
            onClick: () => alert('לחצתי!') 
        }, 'כפתור'),
        React.createElement('ul', {}, [
            React.createElement('li', {}, 'פריט 1'),
            React.createElement('li', {}, 'פריט 2')
        ])
    ]
})
```

<div dir="rtl">

### בפרויקט שלנו - מבנה היררכי מפורט:

</div>

```jsx
// App.jsx - Main entry point
function App() {
    return (
        <AuthProvider>              {/* Context Provider wraps everything */}
            <ProtectedRoute>        {/* HOC for authentication check */}
                <Home />            {/* Protected component */}
            </ProtectedRoute>
        </AuthProvider>
    );
}
```

<div dir="rtl">

**זרימת ה-children בפירוט:**

</div>

```mermaid
graph TD
    A["App returns JSX"] --> B["AuthProvider receives children=ProtectedRoute"]
    B --> C["AuthProvider wraps with Context and returns children"]
    C --> D["ProtectedRoute receives children=Home"]
    D --> E["ProtectedRoute checks authentication"]
    E --> F{User authenticated?}
    F -->|Yes| G["Returns children (Home)"]
    F -->|No| H["Returns Login component"]
```

<div dir="rtl">

### יתרונות של Children Pattern:

</div>

```jsx
// 1. Reusability - reuse same component with different content
<ProtectedRoute>
    <Dashboard />
</ProtectedRoute>

<ProtectedRoute>
    <Settings />
</ProtectedRoute>

<ProtectedRoute>
    <UserProfile />
</ProtectedRoute>

// 2. Composition over Inheritance
<AuthProvider>
    <Router>
        <ProtectedRoute>
            <Layout>
                <Sidebar />
                <MainContent />
            </Layout>
        </ProtectedRoute>
    </Router>
</AuthProvider>

// 3. Flexibility in UI composition
<Modal>
    <ErrorMessage />
    <RetryButton />
</Modal>

<Modal>
    <SuccessIcon />
    <ConfirmationText />
    <OkButton />
</Modal>
```

<div dir="rtl">

## AuthContext - ניהול מצב גלובלי מתקדם

### 1. Context API vs Props Drilling

</div>

```jsx
// Props Drilling problem (without Context)
function App() {
    const [user, setUser] = useState(null);
    return <Header user={user} setUser={setUser} />;
}

function Header({ user, setUser }) {
    return <Navigation user={user} setUser={setUser} />;
}

function Navigation({ user, setUser }) {
    return <UserMenu user={user} setUser={setUser} />;
}

function UserMenu({ user, setUser }) {
    return <button onClick={() => setUser(null)}>Logout</button>;
}

// Solution with Context
function App() {
    return (
        <AuthProvider>
            <Header />
        </AuthProvider>
    );
}

function UserMenu() {
    const { user, logout } = useAuth(); // Direct access without props drilling
    return <button onClick={logout}>Logout</button>;
}
```

<div dir="rtl">

### 2. יצירת AuthContext - צעד אחר צעד

</div>

```jsx
import React, { createContext, useContext, useState, useEffect } from 'react';

// Step 1: Create Context - the "central place" to share data
const AuthContext = createContext();

// Step 2: Custom Hook for convenient Context usage
export const useAuth = () => {
    const context = useContext(AuthContext);
    
    // Error handling - ensure Hook is within Provider
    if (!context) {
        throw new Error('useAuth must be used within an AuthProvider');
    }
    
    return context;
};

// Step 3: Provider Component - supplies data to all children
export const AuthProvider = ({ children }) => {
    // Manage all authentication state in one place
    const [user, setUser] = useState(null);           // Object with user details
    const [accessToken, setAccessToken] = useState(null);
    const [refreshToken, setRefreshToken] = useState(null);
    const [loading, setLoading] = useState(true);     // Prevent flicker during loading
```

<div dir="rtl">

### 3. useEffect לאתחול מצב

</div>

```jsx
// useEffect runs once when component mounts
useEffect(() => {
    console.log('AuthProvider initializing...');
    
    // Check if tokens are stored from previous session
    const storedAccessToken = sessionStorage.getItem('accessToken');
    const storedRefreshToken = sessionStorage.getItem('refreshToken');

    if (storedAccessToken && storedRefreshToken) {
        try {
            console.log('Found stored tokens, validating...');
            
            // Decode token to check if still valid
            const decodedToken = jwtDecode(storedAccessToken);
            console.log('Decoded token:', {
                username: decodedToken.sub,
                expires: new Date(decodedToken.exp * 1000),
                roles: decodedToken.roles
            });

            // Check validity - exp is Unix timestamp in seconds
            const currentTime = Date.now(); // milliseconds
            const expirationTime = decodedToken.exp * 1000; // convert to milliseconds
            
            if (expirationTime > currentTime) {
                // Token valid - restore state from sessionStorage
                setAccessToken(storedAccessToken);
                setRefreshToken(storedRefreshToken);
                setUser(decodedToken); // All info from token
                
                console.log('✓ Valid token loaded from storage');
                console.log('User restored:', decodedToken.sub);
                console.log('Roles:', decodedToken.roles);
            } else {
                // Token expired - clear storage
                console.log('✗ Stored token expired, clearing storage');
                console.log('Token expired at:', new Date(expirationTime));
                console.log('Current time:', new Date(currentTime));
                
                sessionStorage.removeItem('accessToken');
                sessionStorage.removeItem('refreshToken');
            }
        } catch (error) {
            // Invalid token or decode error - clear storage
            console.error('✗ Invalid stored token:', error);
            sessionStorage.removeItem('accessToken');
            sessionStorage.removeItem('refreshToken');
        }
    } else {
        console.log('No stored tokens found');
    }
    
    setLoading(false); // Initialization complete
}, []); // Empty dependency array = runs only once
```

<div dir="rtl">

### 4. פונקציית Login - תהליך מפורט

</div>

```jsx
const login = async (username, password) => {
    console.log('Login attempt for username:', username);

    // Basic validation
    if (!username || !password) {
        console.error('Username or password missing');
        return { success: false, error: 'Username and password are required' };
    }

    try {
        const loginData = { username, password };
        console.log('Sending login request with data:', { username, password: '***' });

        // Send request to Spring Boot server
        const response = await fetch('http://localhost:8080/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(loginData),
        });

        console.log('Login response status:', response.status);

        if (response.ok) {
            // Login successful - receive tokens
            const data = await response.json();
            console.log('Login successful, received tokens');

            // Decode token to extract user info
            const decodedToken = jwtDecode(data.accessToken);

            // Save to sessionStorage (deleted when browser closes)
            sessionStorage.setItem('accessToken', data.accessToken);
            sessionStorage.setItem('refreshToken', data.refreshToken);

            // Update React state
            setAccessToken(data.accessToken);
            setRefreshToken(data.refreshToken);
            setUser(decodedToken); // includes username, roles, IP, etc.

            console.log('User set:', decodedToken.sub);
            return { success: true };
        } else {
            // Login error
            const error = await response.text();
            console.error('Login failed:', error);
            return { success: false, error };
        }
    } catch (error) {
        // Network or technical error
        console.error('Login network error:', error);
        return { success: false, error: 'Network error occurred' };
    }
};
```

<div dir="rtl">

### 5. authenticatedFetch - ה"קסם" של רענון אוטומטי

</div>

```jsx
// Function that wraps fetch and automatically adds:
// 1. JWT token to every request
// 2. Token refresh if needed
// 3. Error handling
const authenticatedFetch = async (url, options = {}) => {
    console.log('authenticatedFetch called for:', url);

    // Basic check for token and user
    if (!accessToken || !user) {
        console.log('No access token or user, redirecting to login');
        await logout();
        throw new Error('No authentication data');
    }

    // Calculate remaining token time
    const tokenExp = user.exp * 1000;           // Convert to milliseconds
    const currentTime = Date.now();
    const timeUntilExpiry = tokenExp - currentTime;

    console.log(`Token expires in: ${Math.floor(timeUntilExpiry / 1000)} seconds`);

    // If token expires in less than 2 minutes (120,000 ms)
    if (timeUntilExpiry < 120000 && timeUntilExpiry > 0) {
        console.log('Token about to expire, attempting refresh...');

        if (!refreshToken) {
            console.log('No refresh token available');
            await logout();
            throw new Error('No refresh token available');
        }

        try {
            // Check that refresh token is also valid
            const refreshDecoded = jwtDecode(refreshToken);
            if (refreshDecoded.exp * 1000 <= Date.now()) {
                console.log('Refresh token expired, logging out...');
                await logout();
                throw new Error('Refresh token expired');
            }

            // Refresh the token
            const newAccessToken = await handleRefreshToken(refreshToken);
            if (!newAccessToken) {
                console.log('Token refresh failed');
                throw new Error('Token refresh failed');
            }

            // Use new token for current request
            options.headers = {
                ...options.headers,
                'Authorization': `Bearer ${newAccessToken}`,
            };
        } catch (refreshError) {
            console.error('Refresh error:', refreshError);
            await logout();
            throw new Error('Session expired');
        }
    } else if (timeUntilExpiry <= 0) {
        // Token already expired
        console.log('Token already expired');
        await logout();
        throw new Error('Token expired');
    } else {
        // Token still valid - normal usage
        options.headers = {
            ...options.headers,
            'Authorization': `Bearer ${accessToken}`,
        };
    }

    console.log('Making authenticated request to:', url);
    return fetch(url, options);
};
```

<div dir="rtl">

### 6. JWT Decode Function - פענוח ידני

</div>

```jsx
// Function to decode JWT token on client side (without verification!)
const jwtDecode = (token) => {
    try {
        // JWT consists of three parts separated by dots: header.payload.signature
        const base64Url = token.split('.')[1];  // Second part is payload
        
        // Convert from base64url to regular base64
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        
        // Decode base64 to JSON string
        const jsonPayload = decodeURIComponent(
            atob(base64)
                .split('')
                .map(function(c) {
                    return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
                })
                .join('')
        );
        
        // Convert to JavaScript object
        return JSON.parse(jsonPayload);
    } catch (error) {
        throw new Error('Invalid token');
    }
};
```

<div dir="rtl">

### 7. handleRefreshToken - רענון טוקנים

</div>

```jsx
const handleRefreshToken = async (refreshTokenToUse = refreshToken) => {
    try {
        console.log('Calling refresh token endpoint with token:', refreshTokenToUse ? 'Token exists' : 'No token');

        const response = await fetch('http://localhost:8080/api/refresh_token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ refreshToken: refreshTokenToUse }),
        });

        console.log('Refresh response status:', response.status);

        if (response.ok) {
            const data = await response.json();
            const decodedToken = jwtDecode(data.accessToken);

            // Update sessionStorage with new tokens
            sessionStorage.setItem('accessToken', data.accessToken);
            sessionStorage.setItem('refreshToken', data.refreshToken);

            // Update React state
            setAccessToken(data.accessToken);
            setRefreshToken(data.refreshToken);
            setUser(decodedToken);

            console.log('Token refresh successful');
            return data.accessToken;
        } else {
            const errorText = await response.text();
            console.error('Refresh failed with status:', response.status, 'Error:', errorText);
            await logout(); // Refresh failed - logout user
            return null;
        }
    } catch (error) {
        console.error('Refresh token error:', error);
        await logout();
        return null;
    }
};
```

<div dir="rtl">

### 8. logout Function - ניקוי מצב

</div>

```jsx
const logout = async () => {
    try {
        // Notify server about logout (blacklist token)
        if (accessToken) {
            await fetch('http://localhost:8080/api/logout', {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${accessToken}` },
            });
        }
    } catch (error) {
        console.error('Logout error:', error);
        // Continue with client-side cleanup even if server request fails
    }

    // Clear sessionStorage
    sessionStorage.removeItem('accessToken');
    sessionStorage.removeItem('refreshToken');

    // Reset React state
    setAccessToken(null);
    setRefreshToken(null);
    setUser(null);
    
    console.log('User logged out successfully');
};
```

<div dir="rtl">

### 9. Context Value Object

</div>

```jsx
// Object that will be provided to all children
const value = {
    user,
    accessToken,
    refreshToken,
    login,
    logout,
    loading,
    authenticatedFetch,
};

return (
    <AuthContext.Provider value={value}>
        {children}
    </AuthContext.Provider>
);
```

<div dir="rtl">

## ProtectedRoute - Higher-Order Component (HOC)

### מושג ה-HOC ב-React

HOC זה **פונקציה שמקבלת קומפוננטה ומחזירה קומפוננטה חדשה** עם פונקציונליות נוספת.

</div>

```jsx
import React from 'react';
import { useAuth } from './AuthContext';
import Login from './Login';

// Component that decides what to display based on authentication state
const ProtectedRoute = ({ children }) => {
    // Use useAuth hook to access authentication state
    const { user, loading } = useAuth();

    // If still in checking process (useEffect in AuthProvider still running)
    if (loading) {
        return (
            <div style={{ padding: '50px', textAlign: 'center' }}>
                <div>Loading...</div>
                {/* Here you can add spinner or skeleton */}
            </div>
        );
    }

    // If no authenticated user - show login page
    if (!user) {
        return <Login />;
    }

    // If authenticated user - show protected content
    return children;
};

export default ProtectedRoute;
```

<div dir="rtl">

**זרימת החלטה ב-ProtectedRoute:**

</div>

```mermaid
graph TD
    A[ProtectedRoute loads] --> B{loading === true?}
    B -->|Yes| C[Show Loading...]
    B -->|No| D{user !== null?}
    D -->|No| E[Show Login Component]
    D -->|Yes| F[Show children - protected content]
    
    G[useAuth hook] --> H[Returns user, loading from AuthContext]
    A --> G
```

<div dir="rtl">

## Login Component - טופס התחברות

</div>

```jsx
import React, { useState } from 'react';
import { useAuth } from './AuthContext';

const Login = () => {
    // Local state for form fields
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    
    // Get login function from AuthContext
    const { login } = useAuth();

    const handleSubmit = async (e) => {
        e.preventDefault(); // Prevent page refresh
        
        // Client-side validation
        if (!username || !password) {
            setError('Please enter both username and password');
            return;
        }

        setLoading(true);
        setError(''); // Clear previous errors

        // Call login function from AuthContext
        const result = await login(username, password);

        if (!result.success) {
            setError(result.error);
        }
        // If success, AuthContext will update and ProtectedRoute will re-render

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

                {/* Error message display */}
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

                <form onSubmit={handleSubmit}>
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
                        type="submit"
                        disabled={loading}
                        style={{
                            width: '100%',
                            padding: '10px',
                            backgroundColor: loading ? '#ccc' : '#1976d2',
                            color: 'white',
                            border: 'none',
                            borderRadius: '4px',
                            cursor: loading ? 'not-allowed' : 'pointer',
                            opacity: loading ? 0.7 : 1
                        }}
                    >
                        {loading ? 'Signing In...' : 'Sign In'}
                    </button>
                </form>
            </div>
        </div>
    );
};

export default Login;
```

<div dir="rtl">

## Home Component - השימוש ב-useAuth Hook

</div>

```jsx
import React, { useState, useEffect } from 'react';
import { useAuth } from './AuthContext';
import TokenDisplay from './TokenDisplay';

const Home = () => {
    // Destructuring everything we need from Context
    const { user, accessToken, refreshToken, logout, authenticatedFetch } = useAuth();
    
    // Local state for content from protected API
    const [protectedMessage, setProtectedMessage] = useState('');

    // useEffect runs when component mounts or accessToken changes
    useEffect(() => {
        const fetchProtectedMessage = async () => {
            try {
                // Use authenticatedFetch that handles token refresh automatically
                const response = await authenticatedFetch('/api/protected-message');

                if (response.ok) {
                    const message = await response.text();
                    setProtectedMessage(message);
                }
            } catch (error) {
                console.error('Error fetching protected message:', error);
                // Error could be from failed token refresh
                // In that case, authenticatedFetch already performed logout
            }
        };

        // Only make request if access token exists
        if (accessToken) {
            fetchProtectedMessage();
        }
    }, [accessToken, authenticatedFetch]); // Dependencies - when they change, useEffect runs again

    // Check if user is admin (RBAC - Role Based Access Control)
    const isAdmin = user?.roles?.includes('ROLE_ADMIN');

    return (
        <div style={{ minHeight: '100vh', backgroundColor: '#f5f5f5' }}>
            {/* Navigation Bar */}
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
                            onClick={logout}  // Function from AuthContext
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

            {/* Main Content */}
            <div style={{ maxWidth: '1200px', margin: '0 auto', padding: '20px' }}>
                {/* Grid Layout with CSS Grid */}
                <div style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
                    gap: '20px'
                }}>

                    {/* User Information Card */}
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
                                {/* Map over roles array */}
                                {user?.roles?.map((role, index) => (
                                    <span
                                        key={index}
                                        style={{
                                            display: 'inline-block',
                                            padding: '3px 8px',
                                            margin: '2px',
                                            // Conditional color based on role
                                            backgroundColor: role === 'ROLE_ADMIN' ? '#ffcdd2' : '#e3f2fd',
                                            color: role === 'ROLE_ADMIN' ? '#d32f2f' : '#1976d2',
                                            borderRadius: '12px',
                                            fontSize: '12px'
                                        }}
                                    >
                                        {role.replace('ROLE_', '')}  {/* Remove prefix */}
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

                        {/* Display protected message if received */}
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

                    {/* Admin Panel - Conditional Rendering */}
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
                                    You have administrative privileges. You can access sensitive system information.
                                </p>
                            </div>

                            {/* System Status Information */}
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
                                </ul>
                            </div>
                        </div>
                    )}
                </div>

                {/* Token Information Display */}
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
                        <strong>Note:</strong> Token times are displayed at page load only.
                        Tokens are automatically refreshed during API activity.
                    </div>

                    <div style={{
                        display: 'grid',
                        gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
                        gap: '15px'
                    }}>
                        {/* Use TokenDisplay component */}
                        <TokenDisplay token={accessToken} label="Access Token" />
                        <TokenDisplay token={refreshToken} label="Refresh Token" />
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Home;
```

<div dir="rtl">

## TokenDisplay Component - פירוק קומפוננטה

</div>

```jsx
import React, { useState, useEffect } from 'react';

// Copy of jwtDecode function (same function from AuthContext)
const jwtDecode = (token) => {
    try {
        const base64Url = token.split('.')[1];
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));
        return JSON.parse(jsonPayload);
    } catch (error) {
        throw new Error('Invalid token');
    }
};

const TokenDisplay = ({ token, label }) => {
    // State for remaining time (calculated once on page load)
    const [timeLeft, setTimeLeft] = useState('');

    useEffect(() => {
        if (!token) {
            setTimeLeft('No token');
            return;
        }

        try {
            // Decode token to extract expiration time
            const decoded = jwtDecode(token);
            const expiryTime = decoded.exp * 1000;  // Convert to milliseconds
            const currentTime = Date.now();
            const difference = expiryTime - currentTime;

            if (difference > 0) {
                // Calculate hours, minutes and seconds
                const hours = Math.floor(difference / 3600000);        // milliseconds to hours
                const minutes = Math.floor((difference % 3600000) / 60000);  // remainder to minutes
                const seconds = Math.floor((difference % 60000) / 1000);     // remainder to seconds

                if (hours > 0) {
                    // Display with hours
                    setTimeLeft(`${hours}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`);
                } else {
                    // Display without hours
                    setTimeLeft(`${minutes}:${seconds.toString().padStart(2, '0')}`);
                }
            } else {
                setTimeLeft('Expired');
            }
        } catch (error) {
            setTimeLeft('Invalid token');
        }
    }, [token]); // Dependency array - when token changes, useEffect runs again

    return (
        <div style={{
            backgroundColor: '#f5f5f5',
            padding: '15px',
            borderRadius: '6px',
            margin: '10px 0'
        }}>
            <h4 style={{ margin: '0 0 10px 0' }}>{label}</h4>
            <div>
                <div style={{ marginBottom: '8px' }}>
                    <strong>Time remaining at page load:</strong>
                    <span style={{
                        color: timeLeft === 'Expired' ? '#d32f2f' : '#2e7d32',
                        fontWeight: 'bold',
                        marginLeft: '5px'
                    }}>
                        {timeLeft}
                    </span>
                </div>
                {/* Display part of token (not all for security reasons) */}
                <div style={{
                    fontSize: '12px',
                    color: '#666',
                    wordBreak: 'break-all',
                    fontFamily: 'monospace',
                    backgroundColor: '#eee',
                    padding: '5px',
                    borderRadius: '3px'
                }}>
                    {token ? `${token.substring(0, 50)}...` : 'No token'}
                </div>
            </div>
        </div>
    );
};

export default TokenDisplay;
```

<div dir="rtl">

## JavaScript/React Concepts מתקדמים

</div>

### 1. Hook Rules

```jsx
// Correct Hook usage
function MyComponent() {
    const [state, setState] = useState(''); // Always at top level
    const { user } = useAuth();              // Always at top level
    
    useEffect(() => {
        // Effect logic
    }, []);
    
    return <div>{state}</div>;
}

// Wrong Hook usage
function MyComponent() {
    if (someCondition) {
        const [state, setState] = useState(''); // Never in conditions!
    }
    
    for (let i = 0; i < 10; i++) {
        useEffect(() => {}); // Never in loops!
    }
}
```

<div dir="rtl">

### 2. Dependency Arrays in useEffect

</div>

```jsx
// No dependencies - runs on every render
useEffect(() => {
    console.log('Runs on every render');
});

// Empty dependencies - runs once on mount
useEffect(() => {
    console.log('Runs once on mount');
}, []);

// With dependencies - runs when dependencies change
useEffect(() => {
    console.log('Runs when accessToken changes');
}, [accessToken]);

// Multiple dependencies
useEffect(() => {
    console.log('Runs when accessToken OR user changes');
}, [accessToken, user]);
```

<div dir="rtl">

### 3. State Updates and Functional Updates

</div>

```jsx
// Direct state update
const [count, setCount] = useState(0);
setCount(count + 1);

// Functional update (safer for race conditions)
setCount(prevCount => prevCount + 1);

// Object state updates
const [user, setUser] = useState({ name: '', email: '' });

// Wrong - mutates existing state
user.name = 'John';
setUser(user);

// Correct - creates new object
setUser(prevUser => ({
    ...prevUser,
    name: 'John'
}));
```

<div dir="rtl">

### 4. Event Handling Patterns

</div>

```jsx
// Inline arrow function (creates new function on each render)
<button onClick={() => handleClick(id)}>Click</button>

// Better - predefined function
const handleButtonClick = useCallback(() => {
    handleClick(id);
}, [id]);

<button onClick={handleButtonClick}>Click</button>

// Form handling
const handleSubmit = (e) => {
    e.preventDefault(); // Prevent page refresh
    // Handle form logic
};

// Input handling
const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
        ...prev,
        [name]: value
    }));
};
```

<div dir="rtl">

### 5. Conditional Rendering Patterns

</div>

```jsx
// Ternary operator
{user ? <Dashboard /> : <Login />}

// Logical AND for optional rendering
{error && <ErrorMessage />}
{isAdmin && <AdminPanel />}

// Conditional with multiple conditions
{user && user.verified && !user.suspended && <FullAccess />}

// Switch-like conditional rendering
const renderContent = () => {
    switch (userRole) {
        case 'admin':
            return <AdminDashboard />;
        case 'user':
            return <UserDashboard />;
        default:
            return <GuestView />;
    }
};
```

<div dir="rtl">

## ממשק התקשורת עם Spring Boot

### 1. API Endpoints שהאפליקציה משתמשת בהם

</div>



```mermaid
graph LR
    A[React App] --> B[POST /api/login]
    A --> C[POST /api/logout]
    A --> D[POST /api/refresh_token]
    A --> E[GET /api/protected-message]
    
    B --> F[החזרת Access + Refresh tokens]
    C --> G[ביטול טוקנים]
    D --> H[טוקנים חדשים]
    E --> I[מידע מוגן]
```

<div dir="rtl">

### 2. Request/Response Examples

</div>

#### Login Request:
```javascript
// Login request structure
POST http://localhost:8080/api/login
Content-Type: application/json

{
    "username": "admin",
    "password": "admin123"
}

// Response structure
{
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```



#### Token Refresh:
```javascript
// Refresh request
POST http://localhost:8080/api/refresh_token
Content-Type: application/json

{
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

#### Protected API Call:
```javascript
// Protected request with Authorization header
GET http://localhost:8080/api/protected-message
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

## JWT Token Structure - מבנה הטוקן

### Payload Example:
```json
{
    "sub": "admin",                                          // Username
    "roles": ["ROLE_ADMIN", "ROLE_USER"],                   // User authorities
    "exp": 1672531200,                                      // Expiration time (Unix timestamp)
    "iat": 1672527600,                                      // Issued at (Unix timestamp)
    "ipAddress": "127.0.0.1",                              // IP binding for security
    "issuedBy": "learning JWT with Spring Security"        // Token issuer
}
```

## זרימת מצב מלאה

```mermaid
stateDiagram-v2
    [*] --> AppLoading: React App starts
    AppLoading --> CheckingStorage: Check sessionStorage
    
    CheckingStorage --> NoTokens: No tokens found
    CheckingStorage --> ValidatingTokens: Tokens found
    
    ValidatingTokens --> TokensValid: Tokens valid
    ValidatingTokens --> TokensInvalid: Tokens invalid/expired
    
    NoTokens --> ShowLogin: Show Login component
    TokensInvalid --> ShowLogin: Clear tokens + show Login
    
    ShowLogin --> AttemptLogin: User enters credentials
    AttemptLogin --> LoginSuccess: Spring Boot validates
    AttemptLogin --> LoginError: Authentication error
    
    LoginError --> ShowLogin: Show error message
    TokensValid --> ShowHome: Navigate to Home
    LoginSuccess --> ShowHome: Save tokens + show Home
    
    ShowHome --> MakingAPICall: API request needed
    MakingAPICall --> CheckTokenExpiry: Check token validity
    
    CheckTokenExpiry --> TokenStillValid: More than 2 minutes left
    CheckTokenExpiry --> NeedRefresh: Less than 2 minutes
    
    TokenStillValid --> APISuccess: Request with current token
    NeedRefresh --> RefreshingToken: Refresh with refreshToken
    
    RefreshingToken --> RefreshSuccess: Spring Boot returns new tokens
    RefreshingToken --> RefreshFailed: Refresh failed
    
    RefreshSuccess --> APISuccess: Request with new token
    RefreshFailed --> ShowLogin: Clear tokens
    APISuccess --> ShowHome: Display response
    
    ShowHome --> LogoutPressed: User clicks Logout
    LogoutPressed --> LoggingOut: Send to Spring Boot
    LoggingOut --> LogoutComplete: Token blacklisted
    LogoutComplete --> ShowLogin: Clear memory tokens
```

<div dir="rtl">

## Best Practices ועקרונות

### 1. State Management
- **Single Source of Truth**: כל מצב האימות ב-AuthContext
- **Immutable Updates**: שימוש ב-spread operator לעדכון state
- **Separation of Concerns**: כל קומפוננטה אחראית על החלק שלה

### 2. Security
- **sessionStorage**: נמחק כשסוגרים את הדפדפן
- **Token Validation**: בדיקת תוקף לפני כל בקשה
- **Automatic Refresh**: רענון שקוף למשתמש
- **Error Handling**: ניקוי אוטומטי במקרה של שגיאות

### 3. User Experience
- **Loading States**: הצגת מצב טעינה
- **Error Messages**: הודעות ברורות למשתמש
- **Automatic Logout**: כשהטוקן פג תוקף
- **Seamless Refresh**: ללא הפרעה לחוויית המשתמש

### 4. Code Organization
- **Custom Hooks**: useAuth לשימוש חוזר
- **Component Composition**: Children pattern
- **HOC Pattern**: ProtectedRoute
- **Modular Structure**: כל קובץ אחראי על דבר אחד

## הרחבות אפשריות

### 1. Remember Me Functionality

</div>

```jsx
const [rememberMe, setRememberMe] = useState(false);

// Choose storage based on user preference
const storage = rememberMe ? localStorage : sessionStorage;
storage.setItem('accessToken', data.accessToken);
```



### 2. Multiple User Sessions
```jsx
// Track active sessions
const [activeSessions, setActiveSessions] = useState([]);

// Display session management
<SessionList sessions={activeSessions} onRevoke={revokeSession} />
```

### 3. Real-time Notifications
```jsx
// WebSocket for security alerts
useEffect(() => {
    const socket = new WebSocket('ws://localhost:8080/security-alerts');
    
    socket.onmessage = (event) => {
        const alert = JSON.parse(event.data);
        if (alert.type === 'SUSPICIOUS_LOGIN') {
            showSecurityAlert(alert.message);
        }
    };
    
    return () => socket.close();
}, []);
```

<div dir="rtl">


אפליקציית React זו מדגימה **JWT authentication מתקדם** עם:

### הישגים טכניים:
- **Context API מתקדם** עם custom hooks
- **Automatic Token Management** עם רענון שקוף
- **Component Composition** עם children pattern
- **Type-safe State Management** עם proper validation
- **Error Handling** מקיף ברמת המערכת

### הישגים UX:
- **Seamless Authentication** ללא הפרעות למשתמש
- **Real-time Token Status** - המשתמש רואה מתי טוקנים פגים
- **Responsive Design** עם CSS Grid
- **Loading States** והודעות שגיאה ברורות
- **Security Transparency** - הצגת מידע אבטחה

המערכת מספקת **foundation חזק** לאפליקציות React מודרניות עם דרישות אבטחה גבוהות.

</div>