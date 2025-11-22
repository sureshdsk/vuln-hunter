import React, { useState, useRef, useEffect } from 'react';
import { useTheme } from '../context/ThemeContext';
import { Moon, Sun, Waves, Sunset, ChevronDown } from 'lucide-react';

const ThemeToggle = () => {
    const { currentTheme, changeTheme, themes } = useTheme();
    const [isOpen, setIsOpen] = useState(false);
    const dropdownRef = useRef(null);

    // Close dropdown when clicking outside
    useEffect(() => {
        const handleClickOutside = (event) => {
            if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
                setIsOpen(false);
            }
        };

        document.addEventListener('mousedown', handleClickOutside);
        return () => document.removeEventListener('mousedown', handleClickOutside);
    }, []);

    const themeIcons = {
        darkCyberpunk: Moon,
        lightModern: Sun,
        oceanBlue: Waves,
        sunsetWarm: Sunset
    };

    const handleThemeChange = (themeId) => {
        changeTheme(themeId);
        setIsOpen(false);
    };

    const CurrentIcon = themeIcons[currentTheme] || Moon;

    return (
        <div className="theme-toggle-container" ref={dropdownRef}>
            <button
                className="theme-toggle-btn"
                onClick={() => setIsOpen(!isOpen)}
                aria-label="Toggle theme"
            >
                <CurrentIcon size={20} />
                <span className="theme-name">{themes[currentTheme]?.name}</span>
                <ChevronDown size={16} className={`chevron ${isOpen ? 'open' : ''}`} />
            </button>

            {isOpen && (
                <div className="theme-dropdown">
                    {Object.entries(themes).map(([themeId, theme]) => {
                        const Icon = themeIcons[themeId];
                        const isActive = currentTheme === themeId;

                        return (
                            <button
                                key={themeId}
                                className={`theme-option ${isActive ? 'active' : ''}`}
                                onClick={() => handleThemeChange(themeId)}
                            >
                                <Icon size={18} />
                                <span>{theme.name}</span>
                                {isActive && <span className="checkmark">✓</span>}
                            </button>
                        );
                    })}
                </div>
            )}
        </div>
    );
};

export default ThemeToggle;
