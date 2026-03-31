"""
app/scenario_services/banking/www.py

Public-facing bank website service template.

Configurable via environment variables:
    BRAND_NAME          Display name (default: from scenario.json)
    BRAND_DOMAIN        Domain for internal links (default: localhost)
    CHAT_URL            URL to chatbot service (default: http://localhost:8081)
    FOUNDED_YEAR        Year established (default: 1952)
    TAGLINE             Slogan (default: Your Regional Banking Partner)
    
Planted findings (controlled via is_finding_active):
    header_vllm_version         X-Powered-By: vLLM/0.4.1
    cors_misconfigured          Wildcard CORS headers
    model_temperature_exposed   X-Model-Config header leak
    debug_mode_enabled          Verbose stack traces on errors
    robots_model_admin          robots.txt discloses /internal/model-admin

Usage in docker-compose.yml:
    command: >
      uvicorn app.scenario_services.banking.www:app
      --host 0.0.0.0 --port 8082
    environment:
      - BRAND_NAME=Fakobanko
      - BRAND_DOMAIN=fakobanko.local
      - CHAT_URL=http://chat.fakobanko.local:8081
"""

import os
import traceback

from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse

from app.scenario_services.common.config import (
    VERBOSE_ERRORS,
    SERVICE_NAME,
    is_finding_active,
    get_or_create_session,
    get_brand_name,
    get_brand_domain,
)


# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

CHAT_URL = os.getenv("CHAT_URL", "http://localhost:8081")
FOUNDED_YEAR = os.getenv("FOUNDED_YEAR", "1952")
TAGLINE = os.getenv("TAGLINE", "Your Regional Banking Partner")


# ═══════════════════════════════════════════════════════════════════════════════
# APP SETUP
# ═══════════════════════════════════════════════════════════════════════════════

app = FastAPI(
    title="Banking Website",
    description="Public-facing bank website",
    version="1.0.0",
)


# ═══════════════════════════════════════════════════════════════════════════════
# ERROR HANDLING
# ═══════════════════════════════════════════════════════════════════════════════

@app.exception_handler(Exception)
async def verbose_exception_handler(request: Request, exc: Exception):
    """
    Finding: debug_mode_enabled
    When active, returns full stack traces on errors.
    """
    if VERBOSE_ERRORS and is_finding_active("debug_mode_enabled"):
        tb = traceback.format_exc()
        return Response(
            content=f"Internal Server Error\n\n{tb}",
            status_code=500,
            media_type="text/plain",
            headers={"X-Debug-Mode": "enabled"},
        )
    return Response(content="Internal Server Error", status_code=500)


# ═══════════════════════════════════════════════════════════════════════════════
# MIDDLEWARE
# ═══════════════════════════════════════════════════════════════════════════════

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add headers based on active findings."""
    response = await call_next(request)

    # Finding: header_vllm_version - leak AI infrastructure version
    if is_finding_active("header_vllm_version"):
        response.headers["X-Powered-By"] = "vLLM/0.4.1"

    # Finding: cors_misconfigured - dangerous CORS settings
    if is_finding_active("cors_misconfigured"):
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Credentials"] = "true"

    # Finding: model_temperature_exposed - leak model config
    if is_finding_active("model_temperature_exposed"):
        response.headers["X-Model-Config"] = "temperature=0.7;top_p=0.9;max_tokens=2048"

    return response


# ═══════════════════════════════════════════════════════════════════════════════
# HTML TEMPLATES
# ═══════════════════════════════════════════════════════════════════════════════

def _page_template(title: str, content: str) -> str:
    """Generate a complete HTML page with consistent styling."""
    brand = get_brand_name()
    domain = get_brand_domain()
    
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} - {brand}</title>
    <style>
        body {{ font-family: Georgia, serif; margin: 0; padding: 0; background: #f5f5f5; }}
        .header {{ background: #1a365d; color: white; padding: 20px; text-align: center; }}
        .header h1 {{ margin: 0; font-size: 2.5em; }}
        .nav {{ background: #2c5282; padding: 10px; text-align: center; }}
        .nav a {{ color: white; margin: 0 20px; text-decoration: none; }}
        .nav a:hover {{ text-decoration: underline; }}
        .content {{ max-width: 800px; margin: 40px auto; padding: 20px; }}
        .hero {{ background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .footer {{ text-align: center; padding: 20px; color: #666; font-size: 0.9em; }}
        ul {{ line-height: 1.8; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🏦 {brand}</h1>
        <p>{TAGLINE} Since {FOUNDED_YEAR}</p>
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
            {content}
        </div>
    </div>
    <div class="footer">
        <p>&copy; 2024 {brand}. Member FDIC. Equal Housing Lender.</p>
    </div>
</body>
</html>"""


# ═══════════════════════════════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/", response_class=HTMLResponse)
async def home():
    """Main landing page."""
    brand = get_brand_name()
    domain = get_brand_domain()
    years = 2024 - int(FOUNDED_YEAR)
    
    content = f"""
        <h2>Welcome to {brand}</h2>
        <p>For over {years} years, {brand} has been serving our community with 
        personalized banking solutions. From checking accounts to home loans, 
        we're here to help you achieve your financial goals.</p>
        <p><strong>Now featuring:</strong> Our new AI-powered customer assistant! 
        Visit <a href="{CHAT_URL}">our chat service</a> to try it out.</p>
    """
    return _page_template("Home", content)


@app.get("/about", response_class=HTMLResponse)
async def about():
    """About page."""
    brand = get_brand_name()
    
    content = f"""
        <h2>About {brand}</h2>
        <p>Founded in {FOUNDED_YEAR} in Montgomery, Alabama, {brand} has grown from a single 
        branch to a regional banking leader with 47 locations across the Southeast.</p>
        <p>Our mission: Banking with a personal touch.</p>
    """
    return _page_template("About Us", content)


@app.get("/services", response_class=HTMLResponse)
async def services():
    """Services page."""
    content = """
        <h2>Our Services</h2>
        <ul>
            <li>Personal Checking & Savings</li>
            <li>Business Banking</li>
            <li>Home Loans & Mortgages</li>
            <li>Auto Loans</li>
            <li>Investment Services</li>
            <li>Online & Mobile Banking</li>
        </ul>
    """
    return _page_template("Services", content)


@app.get("/locations", response_class=HTMLResponse)
async def locations():
    """Locations page."""
    brand = get_brand_name()
    
    content = f"""
        <h2>Branch Locations</h2>
        <p>Find a {brand} branch near you. We have 47 locations across Alabama, 
        Georgia, Tennessee, and Mississippi.</p>
        <p>Use our AI assistant at <a href="{CHAT_URL}">our chat service</a> 
        to find the nearest branch!</p>
    """
    return _page_template("Locations", content)


@app.get("/careers", response_class=HTMLResponse)
async def careers():
    """Careers page - red herring for recon."""
    brand = get_brand_name()
    domain = get_brand_domain()
    
    content = f"""
        <h2>Join Our Team</h2>
        <p>{brand} is always looking for talented individuals to join our growing team.</p>
        <h3>Current Openings</h3>
        <ul>
            <li>Branch Manager - Birmingham, AL</li>
            <li>Loan Officer - Atlanta, GA</li>
            <li>IT Security Analyst - Montgomery, AL (Remote eligible)</li>
            <li>Customer Service Representative - Multiple locations</li>
        </ul>
        <p>To apply, email careers@{domain} with your resume.</p>
    """
    return _page_template("Careers", content)


@app.get("/contact", response_class=HTMLResponse)
async def contact():
    """Contact page."""
    brand = get_brand_name()
    domain = get_brand_domain()
    
    content = f"""
        <h2>Contact Us</h2>
        <p><strong>Customer Service:</strong> 1-800-555-BANK</p>
        <p><strong>Email:</strong> support@{domain}</p>
        <p><strong>Chat:</strong> <a href="{CHAT_URL}">AI Assistant</a></p>
        <p><strong>Headquarters:</strong><br>
        123 Banking Plaza<br>
        Montgomery, AL 36104</p>
    """
    return _page_template("Contact", content)


@app.get("/robots.txt", response_class=PlainTextResponse)
async def robots():
    """
    Finding: robots_model_admin
    Discloses internal paths including /internal/model-admin.
    """
    return """User-agent: *
Allow: /
Disallow: /internal/
Disallow: /internal/model-admin
Disallow: /admin/
Disallow: /api/internal/
"""


@app.get("/internal/model-admin")
async def model_admin():
    """
    Protected endpoint - confirms existence via 403.
    Referenced in robots.txt to guide reconnaissance.
    """
    raise HTTPException(
        status_code=403,
        detail="Access denied. This endpoint requires internal network access.",
    )


@app.get("/health")
async def health():
    """Health check endpoint for Docker/orchestration."""
    session = get_or_create_session()
    brand = get_brand_name()
    
    return {
        "status": "healthy",
        "service": SERVICE_NAME or "banking-www",
        "brand": brand,
        "session_id": session.session_id,
    }
