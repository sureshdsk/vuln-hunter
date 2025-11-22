// Theme configuration with 4 beautiful themes
export const themes = {
  darkCyberpunk: {
    name: 'Dark Cyberpunk',
    id: 'darkCyberpunk',
    colors: {
      // Backgrounds
      'bg-primary': '#0a0a0f',
      'bg-secondary': '#13131f',
      'bg-tertiary': '#1c1c2e',
      'bg-card': '#1a1a2e',
      
      // Accents
      'accent-primary': '#6366f1',
      'accent-secondary': '#8b5cf6',
      'accent-tertiary': '#a855f7',
      'accent-glow': 'rgba(99, 102, 241, 0.5)',
      
      // Text
      'text-primary': '#f8fafc',
      'text-secondary': '#94a3b8',
      'text-muted': '#64748b',
      
      // Borders
      'border-color': '#2d2d42',
      'border-hover': '#4f4f7a',
      
      // Status colors
      'success': '#10b981',
      'error': '#ef4444',
      'warning': '#f59e0b',
      'info': '#3b82f6',
      
      // Effects
      'glass-bg': 'rgba(19, 19, 31, 0.7)',
      'glass-border': 'rgba(255, 255, 255, 0.05)',
      'shadow-color': 'rgba(0, 0, 0, 0.5)',
      'glow-color': 'rgba(99, 102, 241, 0.3)',
    }
  },
  
  lightModern: {
    name: 'Light Modern',
    id: 'lightModern',
    colors: {
      // Backgrounds
      'bg-primary': '#ffffff',
      'bg-secondary': '#f8fafc',
      'bg-tertiary': '#f1f5f9',
      'bg-card': '#ffffff',
      
      // Accents
      'accent-primary': '#6366f1',
      'accent-secondary': '#8b5cf6',
      'accent-tertiary': '#a855f7',
      'accent-glow': 'rgba(99, 102, 241, 0.2)',
      
      // Text
      'text-primary': '#0f172a',
      'text-secondary': '#475569',
      'text-muted': '#94a3b8',
      
      // Borders
      'border-color': '#e2e8f0',
      'border-hover': '#cbd5e1',
      
      // Status colors
      'success': '#10b981',
      'error': '#ef4444',
      'warning': '#f59e0b',
      'info': '#3b82f6',
      
      // Effects
      'glass-bg': 'rgba(255, 255, 255, 0.8)',
      'glass-border': 'rgba(0, 0, 0, 0.05)',
      'shadow-color': 'rgba(0, 0, 0, 0.1)',
      'glow-color': 'rgba(99, 102, 241, 0.15)',
    }
  },
  
  oceanBlue: {
    name: 'Ocean Blue',
    id: 'oceanBlue',
    colors: {
      // Backgrounds
      'bg-primary': '#0a1628',
      'bg-secondary': '#0f1e33',
      'bg-tertiary': '#1a2942',
      'bg-card': '#162338',
      
      // Accents
      'accent-primary': '#06b6d4',
      'accent-secondary': '#0ea5e9',
      'accent-tertiary': '#3b82f6',
      'accent-glow': 'rgba(6, 182, 212, 0.5)',
      
      // Text
      'text-primary': '#f0f9ff',
      'text-secondary': '#7dd3fc',
      'text-muted': '#0891b2',
      
      // Borders
      'border-color': '#1e3a5f',
      'border-hover': '#2e4a6f',
      
      // Status colors
      'success': '#14b8a6',
      'error': '#f43f5e',
      'warning': '#f59e0b',
      'info': '#06b6d4',
      
      // Effects
      'glass-bg': 'rgba(15, 30, 51, 0.7)',
      'glass-border': 'rgba(6, 182, 212, 0.1)',
      'shadow-color': 'rgba(0, 0, 0, 0.5)',
      'glow-color': 'rgba(6, 182, 212, 0.3)',
    }
  },
  
  sunsetWarm: {
    name: 'Sunset Warm',
    id: 'sunsetWarm',
    colors: {
      // Backgrounds
      'bg-primary': '#1a0f1f',
      'bg-secondary': '#2a1a2e',
      'bg-tertiary': '#3a2540',
      'bg-card': '#2d1f35',
      
      // Accents
      'accent-primary': '#f97316',
      'accent-secondary': '#ec4899',
      'accent-tertiary': '#a855f7',
      'accent-glow': 'rgba(249, 115, 22, 0.5)',
      
      // Text
      'text-primary': '#fef3c7',
      'text-secondary': '#fbbf24',
      'text-muted': '#d97706',
      
      // Borders
      'border-color': '#4a2f4f',
      'border-hover': '#6a4f6f',
      
      // Status colors
      'success': '#10b981',
      'error': '#f43f5e',
      'warning': '#fbbf24',
      'info': '#f97316',
      
      // Effects
      'glass-bg': 'rgba(42, 26, 46, 0.7)',
      'glass-border': 'rgba(249, 115, 22, 0.1)',
      'shadow-color': 'rgba(0, 0, 0, 0.5)',
      'glow-color': 'rgba(249, 115, 22, 0.3)',
    }
  }
};

// Helper function to apply theme
export const applyTheme = (themeId) => {
  const theme = themes[themeId];
  if (!theme) return;
  
  const root = document.documentElement;
  Object.entries(theme.colors).forEach(([key, value]) => {
    root.style.setProperty(`--${key}`, value);
  });
};

// Get theme from localStorage or default
export const getSavedTheme = () => {
  return localStorage.getItem('theme') || 'darkCyberpunk';
};

// Save theme to localStorage
export const saveTheme = (themeId) => {
  localStorage.setItem('theme', themeId);
};
