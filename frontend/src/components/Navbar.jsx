import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Shield, LayoutDashboard, FileText } from 'lucide-react';

const Navbar = () => {
    const location = useLocation();

    const isActive = (path) => {
        return location.pathname === path ? 'active' : '';
    };

    return (
        <nav className="navbar">
            <div className="navbar-brand">
                <Shield className="brand-icon" size={28} />
                <span className="brand-text">Vuln-Hunter</span>
            </div>
            <ul className="navbar-links">
                <li>
                    <Link to="/" className={`nav-link ${isActive('/')}`}>
                        <Shield size={20} />
                        <span>Analyze</span>
                    </Link>
                </li>
                <li>
                    <Link to="/dashboard" className={`nav-link ${isActive('/dashboard')}`}>
                        <LayoutDashboard size={20} />
                        <span>Dashboard</span>
                    </Link>
                </li>
            </ul>
        </nav>
    );
};

export default Navbar;
