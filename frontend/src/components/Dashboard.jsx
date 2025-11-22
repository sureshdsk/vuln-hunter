import React, { useState, useEffect } from 'react';

const Dashboard = () => {
    const [jobs, setJobs] = useState([]);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState(null);

    const fetchJobs = async () => {
        setIsLoading(true);
        try {
            const response = await fetch('http://localhost:8000/api/v1/jobs/');
            if (response.ok) {
                const data = await response.json();
                setJobs(data);
                setError(null);
            } else {
                setError('Failed to fetch jobs');
            }
        } catch (err) {
            setError(`Error: ${err.message}`);
        } finally {
            setIsLoading(false);
        }
    };

    useEffect(() => {
        fetchJobs();
    }, []);

    return (
        <div className="dashboard-container">
            <div className="dashboard-header">
                <h2>Analysis Jobs</h2>
                <button className="refresh-btn" onClick={fetchJobs} disabled={isLoading}>
                    {isLoading ? 'Refreshing...' : 'Refresh'}
                </button>
            </div>

            {error && <div className="status-message error">{error}</div>}

            <div className="jobs-table-container">
                <table className="jobs-table">
                    <thead>
                        <tr>
                            <th>Job ID</th>
                            <th>CVE ID</th>
                            <th>Repository</th>
                            <th>Status</th>
                            <th>Date</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {jobs.length === 0 ? (
                            <tr>
                                <td colSpan="6" style={{ textAlign: 'center' }}>No jobs found</td>
                            </tr>
                        ) : (
                            jobs.map((job) => (
                                <tr key={job.id}>
                                    <td title={job.id}>#{job.id.substring(0, 8)}...</td>
                                    <td>{job.cve_id}</td>
                                    <td>{job.repo_url}</td>
                                    <td>
                                        <span className={`status-badge ${job.status.toLowerCase()}`}>
                                            {job.status}
                                        </span>
                                    </td>
                                    <td>{new Date(job.created_at).toLocaleDateString()}</td>
                                    <td>
                                        <button className="view-btn">View Report</button>
                                    </td>
                                </tr>
                            ))
                        )}
                    </tbody>
                </table>
            </div>
        </div>
    );
};

export default Dashboard;
