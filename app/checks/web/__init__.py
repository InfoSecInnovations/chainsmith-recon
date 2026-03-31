"""
Web Checks

HTTP/web-specific reconnaissance:
- Security headers analysis (with value grading)
- Cookie security analysis
- Authentication detection
- WAF/CDN detection
- robots.txt and sitemap discovery
- Path/directory enumeration
- CORS misconfiguration testing
- OpenAPI/Swagger documentation discovery
- Critical findings: WebDAV, VCS exposure, config secrets, directory listing,
  default credentials, debug endpoints (Phase 6a)
- Content & structure discovery: sitemap parsing, redirect chains,
  error page fingerprinting, SSRF indicators (Phase 6c)
- Additional protocol & analysis: favicon fingerprinting, HTTP/2-3 detection,
  HSTS preload verification, SRI check, mass assignment (Phase 6d)
"""

from app.checks.web.headers import HeaderAnalysisCheck
from app.checks.web.robots import RobotsTxtCheck
from app.checks.web.paths import PathProbeCheck
from app.checks.web.cors import CorsCheck
from app.checks.web.openapi import OpenAPICheck
from app.checks.web.webdav import WebDAVCheck
from app.checks.web.vcs_exposure import VCSExposureCheck
from app.checks.web.config_exposure import ConfigExposureCheck
from app.checks.web.directory_listing import DirectoryListingCheck
from app.checks.web.default_creds import DefaultCredsCheck
from app.checks.web.debug_endpoints import DebugEndpointCheck
from app.checks.web.cookie_security import CookieSecurityCheck
from app.checks.web.auth_detection import AuthDetectionCheck
from app.checks.web.waf_detection import WAFDetectionCheck
from app.checks.web.sitemap import SitemapCheck
from app.checks.web.redirect_chain import RedirectChainCheck
from app.checks.web.error_page import ErrorPageCheck
from app.checks.web.ssrf_indicator import SSRFIndicatorCheck
from app.checks.web.favicon import FaviconCheck
from app.checks.web.http2_detection import HTTP2DetectionCheck
from app.checks.web.hsts_preload import HSTSPreloadCheck
from app.checks.web.sri_check import SRICheck
from app.checks.web.mass_assignment import MassAssignmentCheck

__all__ = [
    "HeaderAnalysisCheck",
    "RobotsTxtCheck",
    "PathProbeCheck",
    "CorsCheck",
    "OpenAPICheck",
    "WebDAVCheck",
    "VCSExposureCheck",
    "ConfigExposureCheck",
    "DirectoryListingCheck",
    "DefaultCredsCheck",
    "DebugEndpointCheck",
    "CookieSecurityCheck",
    "AuthDetectionCheck",
    "WAFDetectionCheck",
    "SitemapCheck",
    "RedirectChainCheck",
    "ErrorPageCheck",
    "SSRFIndicatorCheck",
    "FaviconCheck",
    "HTTP2DetectionCheck",
    "HSTSPreloadCheck",
    "SRICheck",
    "MassAssignmentCheck",
]
