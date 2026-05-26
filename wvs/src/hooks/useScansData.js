import { useState, useCallback } from 'react';
import { apiJson, ApiError } from '../lib/api';

const normalizeUrl = (value) => {
  if (!value.startsWith('http://') && !value.startsWith('https://')) {
    return `https://${value}`;
  }
  return value;
};

export const useScansData = ({ onScanComplete } = {}) => {
  const [fullScanUrl, setFullScanUrl] = useState('');
  const [fullScanProfile, setFullScanProfile] = useState('security_only');
  const [fullScanPagePaths, setFullScanPagePaths] = useState('');
  const [fullScanVerifiedTargetId, setFullScanVerifiedTargetId] = useState('');
  const [fullScanEnableAiReview, setFullScanEnableAiReview] = useState(false);
  const [sqlScanUrl, setSqlScanUrl] = useState('');
  const [sslScanUrl, setSslScanUrl] = useState('');
  const [wordpressScanUrl, setWordpressScanUrl] = useState('');
  const [xssScanUrl, setXssScanUrl] = useState('');
  const [techScanUrl, setTechScanUrl] = useState('');
  const [exposureScanUrl, setExposureScanUrl] = useState('');

  const [isFullScanSubmitting, setIsFullScanSubmitting] = useState(false);
  const [isSqlScanning, setIsSqlScanning] = useState(false);
  const [isSslScanning, setIsSslScanning] = useState(false);
  const [isWordpressScanning, setIsWordpressScanning] = useState(false);
  const [isXssScanning, setIsXssScanning] = useState(false);
  const [isTechScanning, setIsTechScanning] = useState(false);
  const [isExposureScanning, setIsExposureScanning] = useState(false);

  const [fullScanJob, setFullScanJob] = useState(null);
  const [sqlScanResult, setSqlScanResult] = useState(null);
  const [sslScanResult, setSslScanResult] = useState(null);
  const [wordpressScanResult, setWordpressScanResult] = useState(null);
  const [xssScanResult, setXssScanResult] = useState(null);
  const [techScanResult, setTechScanResult] = useState(null);
  const [exposureScanResult, setExposureScanResult] = useState(null);

  const [fullScanError, setFullScanError] = useState(null);
  const [sqlError, setSqlError] = useState(null);
  const [sslError, setSslError] = useState(null);
  const [wordpressError, setWordpressError] = useState(null);
  const [xssError, setXssError] = useState(null);
  const [techError, setTechError] = useState(null);
  const [exposureError, setExposureError] = useState(null);

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
  }, [fullScanEnableAiReview, fullScanPagePaths, fullScanProfile, fullScanUrl, fullScanVerifiedTargetId, onScanComplete]);

  const handleSqlScan = useCallback(async () => {
    if (!sqlScanUrl) { setSqlError('Please enter a URL to scan'); return; }
    try {
      setIsSqlScanning(true);
      setSqlError(null);
      const { data } = await apiJson('/scan/sqli', {
        method: 'POST', auth: true, json: true,
        body: { url: normalizeUrl(sqlScanUrl) }
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
  }, [sqlScanUrl, onScanComplete]);

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
        body: { url: normalizeUrl(wordpressScanUrl) }
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
  }, [wordpressScanUrl, onScanComplete]);

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
        body: { url: normalizeUrl(exposureScanUrl) }
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
  }, [exposureScanUrl, onScanComplete]);

  return {
    fullScanUrl, setFullScanUrl, fullScanProfile, setFullScanProfile,
    fullScanPagePaths, setFullScanPagePaths, fullScanVerifiedTargetId, setFullScanVerifiedTargetId,
    fullScanEnableAiReview, setFullScanEnableAiReview, sqlScanUrl, setSqlScanUrl,
    sslScanUrl, setSslScanUrl, wordpressScanUrl, setWordpressScanUrl,
    xssScanUrl, setXssScanUrl, techScanUrl, setTechScanUrl,
    exposureScanUrl, setExposureScanUrl,
    isFullScanSubmitting, isSqlScanning, isSslScanning, isWordpressScanning,
    isXssScanning, isTechScanning, isExposureScanning,
    fullScanJob, setFullScanJob, sqlScanResult, sslScanResult, wordpressScanResult,
    xssScanResult, techScanResult, exposureScanResult,
    fullScanError, sqlError, sslError, wordpressError, xssError, techError, exposureError,
    handleFullScan, handleSqlScan, handleSslScan, handleWordpressScan,
    handleXssScan, handleTechScan, handleExposureScan,
  };
};
