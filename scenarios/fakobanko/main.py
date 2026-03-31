"""
Fakobanko Main Website

Regional bank's public-facing website.
Contains planted findings for the recon lab.
"""

import os
import traceback
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from fakobanko.config import (
    VERBOSE_ERRORS,
    is_finding_active,
    get_or_create_session,
)

app = FastAPI(
    title="Fakobanko - Your Regional Banking Partner",
    description="Fakobanko main website",
    version="1.0.0",
)


# Custom exception handler for verbose errors
@app.exception_handler(Exception)
async def verbose_exception_handler(request: Request, exc: Exception):
    if VERBOSE_ERRORS and is_finding_active("debug_mode_enabled"):
        tb = traceback.format_exc()
        return Response(
            content=f"Internal Server Error\n\n{tb}",
            status_code=500,
            media_type="text/plain",
            headers={"X-Debug-Mode": "enabled"}
        )
    return Response(content="Internal Server Error", status_code=500)


@app.middleware("http")
async def add_headers(request: Request, call_next):
    response = await call_next(request)
    
    # Always leak vLLM version (certain finding)
    if is_finding_active("header_vllm_version"):
        response.headers["X-Powered-By"] = "vLLM/0.4.1"
    
    # Conditional CORS misconfiguration
    if is_finding_active("cors_misconfigured"):
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Credentials"] = "true"
    
    # Model temperature leak
    if is_finding_active("model_temperature_exposed"):
        response.headers["X-Model-Config"] = "temperature=0.7;top_p=0.9;max_tokens=2048"
    
    return response


@app.get("/", response_class=HTMLResponse)
async def home():
    """Main landing page."""
    return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Fakobanko - Your Regional Banking Partner</title>
    <style>
        body { font-family: Georgia, serif; margin: 0; padding: 0; background: #f5f5f5; }
        .header { background: #1a365d; color: white; padding: 20px; text-align: center; }
        .header h1 { margin: 0; font-size: 2.5em; }
        .nav { background: #2c5282; padding: 10px; text-align: center; }
        .nav a { color: white; margin: 0 20px; text-decoration: none; }
        .content { max-width: 800px; margin: 40px auto; padding: 20px; }
        .hero { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .footer { text-align: center; padding: 20px; color: #666; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🏦 Fakobanko</h1>
        <p>Your Regional Banking Partner Since 1952</p>
    </div>
    <div class="nav">
        <a href="/">Home</a>
        <a href="/about">About Us</a>
        <a href="/services">Services</a>
        <a href="/locations">Locations</a>
        <a href="/careers">Careers</a>
        <a href="/contact">Contact</a>
    </div>
    <div class="content">
        <div class="hero">
            <h2>Welcome to Fakobanko</h2>
            <p>For over 70 years, Fakobanko has been serving our community with 
            personalized banking solutions. From checking accounts to home loans, 
            we're here to help you achieve your financial goals.</p>
            <p><strong>Now featuring:</strong> Our new AI-powered customer assistant! 
            Visit <a href="http://chat.fakobanko.local:8081">chat.fakobanko.local</a> 
            to try it out.</p>
        </div>
    </div>
    <div class="footer">
        <p>&copy; 2024 Fakobanko. Member FDIC. Equal Housing Lender.</p>
    </div>
</body>
</html>
"""


@app.get("/robots.txt", response_class=PlainTextResponse)
async def robots():
    """robots.txt with planted disclosure."""
    content = """User-agent: *
Allow: /
Disallow: /internal/
Disallow: /internal/model-admin
Disallow: /admin/
Disallow: /api/internal/
"""
    # Certain finding: robots_model_admin
    return content


@app.get("/internal/model-admin")
async def model_admin():
    """Protected endpoint - confirms existence via 403."""
    raise HTTPException(
        status_code=403,
        detail="Access denied. This endpoint requires internal network access."
    )


@app.get("/about", response_class=HTMLResponse)
async def about():
    """About page - normal content."""
    return """
<!DOCTYPE html>
<html><head><title>About - Fakobanko</title></head>
<body>
<h1>About Fakobanko</h1>
<p>Founded in 1952 in Montgomery, Alabama, Fakobanko has grown from a single 
branch to a regional banking leader with 47 locations across the Southeast.</p>
<p>Our mission: Banking with a personal touch.</p>
</body></html>
"""


@app.get("/careers", response_class=HTMLResponse)
async def careers():
    """Careers page - red herring for recon."""
    return """
<!DOCTYPE html>
<html><head><title>Careers - Fakobanko</title></head>
<body>
<h1>Join Our Team</h1>
<p>Fakobanko is always looking for talented individuals to join our growing team.</p>
<h2>Current Openings</h2>
<ul>
    <li>Branch Manager - Birmingham, AL</li>
    <li>Loan Officer - Atlanta, GA</li>
    <li>IT Security Analyst - Montgomery, AL (Remote eligible)</li>
    <li>Customer Service Representative - Multiple locations</li>
</ul>
<p>To apply, email careers@fakobanko.local with your resume.</p>
</body></html>
"""


@app.get("/services", response_class=HTMLResponse)
async def services():
    return """
<!DOCTYPE html>
<html><head><title>Services - Fakobanko</title></head>
<body>
<h1>Our Services</h1>
<ul>
    <li>Personal Checking & Savings</li>
    <li>Business Banking</li>
    <li>Home Loans & Mortgages</li>
    <li>Auto Loans</li>
    <li>Investment Services</li>
    <li>Online & Mobile Banking</li>
</ul>
</body></html>
"""


@app.get("/locations", response_class=HTMLResponse)
async def locations():
    return """
<!DOCTYPE html>
<html><head><title>Locations - Fakobanko</title></head>
<body>
<h1>Branch Locations</h1>
<p>Find a Fakobanko branch near you. We have 47 locations across Alabama, 
Georgia, Tennessee, and Mississippi.</p>
<p>Use our AI assistant at <a href="http://chat.fakobanko.local:8081">chat.fakobanko.local</a> 
to find the nearest branch!</p>
</body></html>
"""


@app.get("/contact", response_class=HTMLResponse)
async def contact():
    return """
<!DOCTYPE html>
<html><head><title>Contact - Fakobanko</title></head>
<body>
<h1>Contact Us</h1>
<p><strong>Customer Service:</strong> 1-800-FAKO-BANK</p>
<p><strong>Email:</strong> support@fakobanko.local</p>
<p><strong>Chat:</strong> <a href="http://chat.fakobanko.local:8081">AI Assistant</a></p>
<p><strong>Headquarters:</strong><br>
123 Banking Plaza<br>
Montgomery, AL 36104</p>
</body></html>
"""


# Health check
@app.get("/health")
async def health():
    session = get_or_create_session()
    return {
        "status": "healthy",
        "service": "fakobanko-web",
        "session_id": session.session_id,
    }
