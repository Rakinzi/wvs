import { useState, useCallback, useEffect } from 'react';
import { apiJson, ApiError } from '../lib/api';
import { apiDateMs } from '../lib/time';

const normalizeUrl = (value) => {
  if (!value.startsWith('http://') && !value.startsWith('https://')) {
    return `https://${value}`;
  }
  return value;
};

function useLocalStorage(key, defaultValue) {
  const [value, setValue] = useState(() => {
    try {
      const stored = localStorage.getItem(key);
      return stored !== null ? JSON.parse(stored) : defaultValue;
    } catch {
      return defaultValue;
    }
  });

  const set = useCallback((next) => {
    setValue(prev => {
      const resolved = typeof next === 'function' ? next(prev) : next;
      try {
        if (resolved === null || resolved === undefined) {
          localStorage.removeItem(key);
        } else {
          localStorage.setItem(key, JSON.stringify(resolved));
        }
      } catch { /* storage full — degrade gracefully */ }
      return resolved;
    });
  }, [key]);

  return [value, set];
}

const TERMINAL_JOB_STATUSES = ['completed', 'failed'];
const ACTIVE_JOB_STATUSES = ['queued', 'running'];

const toTimestamp = (value) => {
  return apiDateMs(value);
};

const chooseLatestJob = (storedJob, jobs) => {
  if (!Array.isArray(jobs) || jobs.length === 0) {
    return storedJob ?? null;
  }

  const latestActiveJob = jobs.find((job) => ACTIVE_JOB_STATUSES.includes(job.status)) || null;
  const latestJob = jobs[0] || null;

  if (!storedJob) {
    return latestActiveJob || latestJob;
  }

  const storedJobTimestamp = toTimestamp(storedJob.created_at);
  const latestActiveTimestamp = toTimestamp(latestActiveJob?.created_at);
  const latestJobTimestamp = toTimestamp(latestJob?.created_at);

  if (latestActiveJob && latestActiveJob.id !== storedJob.id && latestActiveTimestamp >= storedJobTimestamp) {
    return latestActiveJob;
  }

  if (TERMINAL_JOB_STATUSES.includes(storedJob.status) && latestJob && latestJob.id !== storedJob.id && latestJobTimestamp >= storedJobTimestamp) {
    return latestJob;
  }

  return storedJob;
};

export const useScansData = ({ onScanComplete } = {}) => {
  // URL inputs — persist so user doesn't re-type after navigation
  const [fullScanUrl, setFullScanUrl]               = useLocalStorage('scan_url_full', '');
  const [fullScanProfile, setFullScanProfile]       = useLocalStorage('scan_profile', 'security_only');
  const [fullScanPagePaths, setFullScanPagePaths]   = useLocalStorage('scan_page_paths', '');
  const [fullScanVerifiedTargetId, setFullScanVerifiedTargetId] = useLocalStorage('scan_verified_target_id', '');
  const [fullScanEnableAiReview, setFullScanEnableAiReview]     = useLocalStorage('scan_ai_review', false);
  const [fullScanEnableActiveChecks, setFullScanEnableActiveChecks] = useLocalStorage('scan_active_checks', false);
  const [fullScanActiveCheckPaths, setFullScanActiveCheckPaths] = useLocalStorage('scan_active_check_paths', '');
  const [fullScanActiveCheckBudget, setFullScanActiveCheckBudget] = useLocalStorage('scan_active_check_budget', 8);
  const [fullScanAuthAccounts, setFullScanAuthAccounts] = useLocalStorage('scan_auth_accounts', '');
  const [fullScanProtectedPaths, setFullScanProtectedPaths] = useLocalStorage('scan_protected_paths', '');
  const [fullScanIdorPaths, setFullScanIdorPaths] = useLocalStorage('scan_idor_paths', '');
  const [sqlScanUrl, setSqlScanUrl]                 = useLocalStorage('scan_url_sql', '');
  const [sslScanUrl, setSslScanUrl]                 = useLocalStorage('scan_url_ssl', '');
  const [wordpressScanUrl, setWordpressScanUrl]     = useLocalStorage('scan_url_wordpress', '');
  const [xssScanUrl, setXssScanUrl]                 = useLocalStorage('scan_url_xss', '');
  const [techScanUrl, setTechScanUrl]               = useLocalStorage('scan_url_tech', '');
  const [exposureScanUrl, setExposureScanUrl]       = useLocalStorage('scan_url_exposure', '');
  const [malwareScanUrl, setMalwareScanUrl]         = useLocalStorage('scan_url_malware', '');

  // In-flight flags — not persisted (always false on load)
  const [isFullScanSubmitting, setIsFullScanSubmitting] = useState(false);
  const [isSqlScanning, setIsSqlScanning]               = useState(false);
  const [isSslScanning, setIsSslScanning]               = useState(false);
  const [isWordpressScanning, setIsWordpressScanning]   = useState(false);
  const [isXssScanning, setIsXssScanning]               = useState(false);
  const [isTechScanning, setIsTechScanning]             = useState(false);
  const [isExposureScanning, setIsExposureScanning]     = useState(false);
  const [isMalwareScanning, setIsMalwareScanning]       = useState(false);

  // Results — persisted so navigating away and back shows last result
  const [fullScanJob, setFullScanJob]               = useLocalStorage('scan_job_full', null);
  const [sqlScanResult, setSqlScanResult]           = useLocalStorage('scan_result_sql', null);
  const [sslScanResult, setSslScanResult]           = useLocalStorage('scan_result_ssl', null);
  const [wordpressScanResult, setWordpressScanResult] = useLocalStorage('scan_result_wordpress', null);
  const [xssScanResult, setXssScanResult]           = useLocalStorage('scan_result_xss', null);
  const [techScanResult, setTechScanResult]         = useLocalStorage('scan_result_tech', null);
  const [exposureScanResult, setExposureScanResult] = useLocalStorage('scan_result_exposure', null);
  const [malwareScanResult, setMalwareScanResult]   = useLocalStorage('scan_result_malware', null);

  // Error state — not persisted
  const [fullScanError, setFullScanError]     = useState(null);
  const [sqlError, setSqlError]               = useState(null);
  const [sslError, setSslError]               = useState(null);
  const [wordpressError, setWordpressError]   = useState(null);
  const [xssError, setXssError]               = useState(null);
  const [techError, setTechError]             = useState(null);
  const [exposureError, setExposureError]     = useState(null);
  const [malwareError, setMalwareError]       = useState(null);

  useEffect(() => {
    let cancelled = false;

    apiJson('/scan/jobs?limit=5', { auth: true })
      .then(({ data }) => {
        if (cancelled || data.status !== 'success') {
          return;
        }
        const resolvedJob = chooseLatestJob(fullScanJob, data.jobs || []);
        if (resolvedJob && resolvedJob.id !== fullScanJob?.id) {
          setFullScanJob(resolvedJob);
          return;
        }
        if (!resolvedJob && fullScanJob) {
          setFullScanJob(null);
        }
      })
      .catch(() => {});

    return () => {
      cancelled = true;
    };
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Poll the full scan job whenever it's in-progress (survives tab switches and reloads)
  useEffect(() => {
    if (!fullScanJob || !ACTIVE_JOB_STATUSES.includes(fullScanJob.status)) return;

    const poll = () => {
      apiJson(`/scan/jobs/${fullScanJob.id}`, { auth: true })
        .then(({ data }) => { if (data.status === 'success') setFullScanJob(data.job); })
        .catch(() => {});
    };

    poll(); // immediate fetch on mount / status change
    const id = setInterval(poll, 3000);
    return () => clearInterval(id);
  }, [fullScanJob?.id, fullScanJob?.status]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleFullScan = useCallback(async () => {
    if (!fullScanUrl) { setFullScanError('Please enter a URL to scan'); return; }
    try {
      setIsFullScanSubmitting(true);
      setFullScanError(null);
      const { data } = await apiJson('/scan', {
        method: 'POST', auth: true, json: true,
        body: {
          url: normalizeUrl(fullScanUrl),
          scan_profile: fullScanProfile,
          page_paths: fullScanPagePaths
            .split('\n')
            .map((item) => item.trim())
            .filter(Boolean),
          verified_target_id: fullScanVerifiedTargetId || undefined,
          enable_ai_review: fullScanEnableAiReview,
          enable_active_checks: fullScanEnableActiveChecks,
          active_check_paths: fullScanActiveCheckPaths
            .split('\n')
            .map((item) => item.trim())
            .filter(Boolean),
          active_check_budget: Number(fullScanActiveCheckBudget) || 8,
          auth_test_accounts: fullScanAuthAccounts
            .split('\n')
            .map((item) => item.trim())
            .filter(Boolean)
            .map((line) => {
              const [identifier, password, role] = line.split('|').map((part) => part?.trim());
              return identifier?.includes('@')
                ? { email: identifier, password, role: role || undefined }
                : { username: identifier, password, role: role || undefined };
            }),
          protected_paths: fullScanProtectedPaths
            .split('\n')
            .map((item) => item.trim())
            .filter(Boolean),
          idor_paths: fullScanIdorPaths
            .split('\n')
            .map((item) => item.trim())
            .filter(Boolean),
        }
      });
      if (data.status === 'accepted') {
        setFullScanJob({
          id: data.job_id, task_id: data.task_id, url: data.url,
          status: 'queued', created_at: data.timestamp, result_id: null, progress: null, scan_type: data.scan_profile
        });
        onScanComplete?.();
      } else {
        throw new Error(data.message || 'Failed to queue scan');
      }
    } catch (error) {
      setFullScanError(error instanceof ApiError ? error.message : 'Failed to queue scan');
    } finally {
      setIsFullScanSubmitting(false);
    }
  }, [fullScanActiveCheckBudget, fullScanActiveCheckPaths, fullScanAuthAccounts, fullScanEnableActiveChecks, fullScanEnableAiReview, fullScanIdorPaths, fullScanPagePaths, fullScanProfile, fullScanProtectedPaths, fullScanUrl, fullScanVerifiedTargetId, onScanComplete]);

  const handleSqlScan = useCallback(async () => {
    if (!sqlScanUrl) { setSqlError('Please enter a URL to scan'); return; }
    try {
      setIsSqlScanning(true);
      setSqlError(null);
      const { data } = await apiJson('/scan/sqli', {
        method: 'POST', auth: true, json: true,
        body: {
          url: normalizeUrl(sqlScanUrl),
          verified_target_id: fullScanVerifiedTargetId || undefined,
          enable_active_checks: fullScanEnableActiveChecks,
        }
      });
      if (data.status === 'success') {
        setSqlScanResult({
          url: data.url,
          scan_id: data.scan_id,
          timestamp: new Date().toISOString(),
          vulnerable: data.vulnerable,
          findings: data.findings || [],
          recommendations: data.recommendations || []
        });
        onScanComplete?.();
      } else {
        throw new Error(data.message || 'Failed to perform SQL injection scan');
      }
    } catch (error) {
      setSqlError(error instanceof ApiError ? error.message : 'Failed to perform scan. Please try again.');
    } finally {
      setIsSqlScanning(false);
    }
  }, [fullScanEnableActiveChecks, fullScanVerifiedTargetId, sqlScanUrl, onScanComplete]);

  const handleSslScan = useCallback(async () => {
    if (!sslScanUrl) { setSslError('Please enter a URL to scan'); return; }
    try {
      setIsSslScanning(true);
      setSslError(null);
      const { data } = await apiJson('/scan/ssl', {
        method: 'POST', auth: true, json: true,
        body: { url: normalizeUrl(sslScanUrl) }
      });
      if (data.status === 'success') {
        setSslScanResult({
          url: data.url,
          scan_id: data.scan_id,
          timestamp: new Date().toISOString(),
          findings: data.findings || { valid: false, error: 'No findings returned from scan' },
          recommendations: data.recommendations || []
        });
        onScanComplete?.();
      } else {
        throw new Error(data.message || 'Failed to perform SSL/TLS scan');
      }
    } catch (error) {
      setSslError(error instanceof ApiError ? error.message : 'Failed to perform scan. Please try again.');
    } finally {
      setIsSslScanning(false);
    }
  }, [sslScanUrl, onScanComplete]);

  const handleWordpressScan = useCallback(async () => {
    if (!wordpressScanUrl) { setWordpressError('Please enter a URL to scan'); return; }
    try {
      setIsWordpressScanning(true);
      setWordpressError(null);
      const { data } = await apiJson('/scan/wordpress', {
        method: 'POST', auth: true, json: true,
        body: {
          url: normalizeUrl(wordpressScanUrl),
          verified_target_id: fullScanVerifiedTargetId || undefined,
          enable_active_checks: fullScanEnableActiveChecks,
        }
      });
      if (data.status === 'success') {
        setWordpressScanResult({
          url: data.url,
          scan_id: data.scan_id,
          timestamp: new Date().toISOString(),
          findings: data.findings || {},
          recommendations: data.recommendations || [],
          summary: data.summary || {}
        });
        onScanComplete?.();
      } else {
        throw new Error(data.message || 'Failed to perform WordPress scan');
      }
    } catch (error) {
      setWordpressError(error instanceof ApiError ? error.message : 'Failed to perform scan. Please try again.');
    } finally {
      setIsWordpressScanning(false);
    }
  }, [fullScanEnableActiveChecks, fullScanVerifiedTargetId, wordpressScanUrl, onScanComplete]);

  const handleXssScan = useCallback(async () => {
    if (!xssScanUrl) { setXssError('Please enter a URL to scan'); return; }
    try {
      setIsXssScanning(true);
      setXssError(null);
      const { data } = await apiJson('/scan/xss', {
        method: 'POST', auth: true, json: true,
        body: { url: normalizeUrl(xssScanUrl) }
      });
      if (data.status === 'success') {
        setXssScanResult({
          url: data.url,
          scan_id: data.scan_id,
          timestamp: new Date().toISOString(),
          vulnerable: data.vulnerable,
          findings: data.findings || {},
          recommendations: data.recommendations || [],
        });
        onScanComplete?.();
      } else {
        throw new Error(data.message || 'Failed to perform XSS scan');
      }
    } catch (error) {
      setXssError(error instanceof ApiError ? error.message : 'Failed to perform scan. Please try again.');
    } finally {
      setIsXssScanning(false);
    }
  }, [xssScanUrl, onScanComplete]);

  const handleTechScan = useCallback(async () => {
    if (!techScanUrl) { setTechError('Please enter a URL to scan'); return; }
    try {
      setIsTechScanning(true);
      setTechError(null);
      const { data } = await apiJson('/scan/tech', {
        method: 'POST', auth: true, json: true,
        body: { url: normalizeUrl(techScanUrl) }
      });
      if (data.status === 'success') {
        setTechScanResult({
          url: data.url,
          scan_id: data.scan_id,
          timestamp: new Date().toISOString(),
          technologies: data.technologies || {},
          findings: data.findings || {},
          recommendations: data.recommendations || [],
        });
        onScanComplete?.();
      } else {
        throw new Error(data.message || 'Failed to perform tech scan');
      }
    } catch (error) {
      setTechError(error instanceof ApiError ? error.message : 'Failed to perform scan. Please try again.');
    } finally {
      setIsTechScanning(false);
    }
  }, [techScanUrl, onScanComplete]);

  const handleExposureScan = useCallback(async () => {
    if (!exposureScanUrl) { setExposureError('Please enter a URL to scan'); return; }
    try {
      setIsExposureScanning(true);
      setExposureError(null);
      const { data } = await apiJson('/scan/exposure', {
        method: 'POST', auth: true, json: true,
        body: {
          url: normalizeUrl(exposureScanUrl),
          verified_target_id: fullScanVerifiedTargetId || undefined,
          enable_active_checks: fullScanEnableActiveChecks,
        }
      });
      if (data.status === 'success') {
        setExposureScanResult({
          url: data.url,
          scan_id: data.scan_id,
          timestamp: new Date().toISOString(),
          vulnerable: data.vulnerable,
          findings: data.findings || {},
          recommendations: data.recommendations || [],
        });
        onScanComplete?.();
      } else {
        throw new Error(data.message || 'Failed to perform exposure scan');
      }
    } catch (error) {
      setExposureError(error instanceof ApiError ? error.message : 'Failed to perform scan. Please try again.');
    } finally {
      setIsExposureScanning(false);
    }
  }, [exposureScanUrl, fullScanEnableActiveChecks, fullScanVerifiedTargetId, onScanComplete]);

  const handleMalwareScan = useCallback(async () => {
    if (!malwareScanUrl) { setMalwareError('Please enter a URL to scan'); return; }
    try {
      setIsMalwareScanning(true);
      setMalwareError(null);
      const { data } = await apiJson('/scan/malware', {
        method: 'POST', auth: true, json: true,
        body: { url: normalizeUrl(malwareScanUrl) }
      });
      if (data.status === 'success') {
        setMalwareScanResult({
          url: data.url,
          scan_id: data.scan_id,
          timestamp: new Date().toISOString(),
          vulnerable: data.vulnerable,
          findings: data.findings || {},
          recommendations: data.recommendations || [],
        });
        onScanComplete?.();
      } else {
        throw new Error(data.message || 'Failed to perform malware analysis');
      }
    } catch (error) {
      setMalwareError(error instanceof ApiError ? error.message : 'Failed to perform scan. Please try again.');
    } finally {
      setIsMalwareScanning(false);
    }
  }, [malwareScanUrl, onScanComplete]);

  return {
    fullScanUrl, setFullScanUrl, fullScanProfile, setFullScanProfile,
    fullScanPagePaths, setFullScanPagePaths, fullScanVerifiedTargetId, setFullScanVerifiedTargetId,
    fullScanEnableAiReview, setFullScanEnableAiReview,
    fullScanEnableActiveChecks, setFullScanEnableActiveChecks,
    fullScanActiveCheckPaths, setFullScanActiveCheckPaths,
    fullScanActiveCheckBudget, setFullScanActiveCheckBudget,
    fullScanAuthAccounts, setFullScanAuthAccounts,
    fullScanProtectedPaths, setFullScanProtectedPaths,
    fullScanIdorPaths, setFullScanIdorPaths,
    sqlScanUrl, setSqlScanUrl,
    sslScanUrl, setSslScanUrl, wordpressScanUrl, setWordpressScanUrl,
    xssScanUrl, setXssScanUrl, techScanUrl, setTechScanUrl,
    exposureScanUrl, setExposureScanUrl, malwareScanUrl, setMalwareScanUrl,
    isFullScanSubmitting, isSqlScanning, isSslScanning, isWordpressScanning,
    isXssScanning, isTechScanning, isExposureScanning, isMalwareScanning,
    fullScanJob, setFullScanJob, sqlScanResult, sslScanResult, wordpressScanResult,
    xssScanResult, techScanResult, exposureScanResult, malwareScanResult,
    fullScanError, sqlError, sslError, wordpressError, xssError, techError, exposureError, malwareError,
    handleFullScan, handleSqlScan, handleSslScan, handleWordpressScan,
    handleXssScan, handleTechScan, handleExposureScan, handleMalwareScan,
  };
};
