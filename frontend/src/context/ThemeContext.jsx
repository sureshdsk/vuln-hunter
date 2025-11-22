import React, { createContext, useContext, useState, useEffect } from 'react';
import { themes, applyTheme, getSavedTheme, saveTheme } from '../config/themes';

const ThemeContext = createContext();

export const useTheme = () => {
    const context = useContext(ThemeContext);
    if (!context) {
        throw new Error('useTheme must be used within ThemeProvider');
    }
    return context;
};

export const ThemeProvider = ({ children }) => {
    const [currentTheme, setCurrentTheme] = useState(getSavedTheme());

    useEffect(() => {
        // Apply theme on mount and when theme changes
        applyTheme(currentTheme);
    }, [currentTheme]);

    const changeTheme = (themeId) => {
        setCurrentTheme(themeId);
        saveTheme(themeId);
        applyTheme(themeId);
    };

    const value = {
        currentTheme,
        changeTheme,
        themes,
        themeName: themes[currentTheme]?.name || 'Dark Cyberpunk'
    };

    return (
        <ThemeContext.Provider value={value}>
            {children}
        </ThemeContext.Provider>
    );
};

export default ThemeContext;
