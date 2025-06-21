import React, { useState, useEffect } from 'react';

// Simple JWT decode function
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
    const [timeLeft, setTimeLeft] = useState('');

    useEffect(() => {
        if (!token) {
            setTimeLeft('No token');
            return;
        }

        try {
            const decoded = jwtDecode(token);
            const expiryTime = decoded.exp * 1000;
            const currentTime = Date.now();
            const difference = expiryTime - currentTime;

            if (difference > 0) {
                const hours = Math.floor(difference / 3600000);
                const minutes = Math.floor((difference % 3600000) / 60000);
                const seconds = Math.floor((difference % 60000) / 1000);

                if (hours > 0) {
                    setTimeLeft(`${hours}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`);
                } else {
                    setTimeLeft(`${minutes}:${seconds.toString().padStart(2, '0')}`);
                }
            } else {
                setTimeLeft('Expired');
            }
        } catch (error) {
            setTimeLeft('Invalid token');
        }
    }, [token]);

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