import React, { useState } from 'react';

const SubmissionForm = () => {
  const [cveId, setCveId] = useState('');
  const [repoUrl, setRepoUrl] = useState('');
  const [status, setStatus] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setStatus('');

    try {
      const response = await fetch('http://localhost:8000/api/v1/jobs/create/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          cve_id: cveId,
          repo_url: repoUrl,
          branch: 'main' // Default branch
        }),
      });

      if (response.ok) {
        const data = await response.json();
        setStatus(`Submission successful! Job ID: ${data.id}`);
        setCveId('');
        setRepoUrl('');
      } else {
        const data = await response.json();
        setStatus(`Error: ${JSON.stringify(data) || 'Submission failed'}`);
      }
    } catch (error) {
      setStatus(`Error: ${error.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="submission-form-container">
      <h2>Submit Vulnerability Analysis</h2>
      <form onSubmit={handleSubmit} className="submission-form">
        <div className="form-group">
          <label htmlFor="cveId">CVE ID:</label>
          <input
            type="text"
            id="cveId"
            value={cveId}
            onChange={(e) => setCveId(e.target.value)}
            placeholder="CVE-2023-12345"
            required
          />
        </div>
        <div className="form-group">
          <label htmlFor="repoUrl">GitHub Repo URL:</label>
          <input
            type="url"
            id="repoUrl"
            value={repoUrl}
            onChange={(e) => setRepoUrl(e.target.value)}
            placeholder="https://github.com/user/repo"
            required
          />
        </div>
        <button type="submit" disabled={isLoading}>
          {isLoading ? 'Submitting...' : 'Analyze'}
        </button>
      </form>
      {status && <div className={`status-message ${status.startsWith('Error') ? 'error' : 'success'}`}>{status}</div>}
    </div>
  );
};

export default SubmissionForm;
