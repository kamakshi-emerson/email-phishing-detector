import asyncio
import asyncio as _asyncio

import time as _time
from observability.observability_wrapper import (
    trace_agent, trace_step, trace_step_sync, trace_model_call, trace_tool_call,
)
from config import settings as _obs_settings

import logging as _obs_startup_log
from contextlib import asynccontextmanager
from observability.instrumentation import initialize_tracer

_obs_startup_logger = _obs_startup_log.getLogger(__name__)

from modules.guardrails.content_safety_decorator import with_content_safety

GUARDRAILS_CONFIG = {
    'content_safety_enabled': True,
    'runtime_enabled': True,
    'content_safety_severity_threshold': 3,
    'check_toxicity': True,
    'check_jailbreak': True,
    'check_pii_input': False,
    'check_credentials_output': True,
    'check_output': True,
    'check_toxic_code_output': True,
    'sanitize_pii': False
}

import logging
import json
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ValidationError, field_validator
from pathlib import Path
import email
from email import policy
from email.parser import BytesParser
import re

from config import Config

# System prompt and output format constants
SYSTEM_PROMPT = (
    "You are a formal, detail-oriented email security analysis agent. Your primary role is to review provided emails and determine if they are phishing or suspicious. For each email, analyze the content, links, sender information, and any metadata. Clearly flag emails that are likely phishing or suspicious, and provide a concise explanation for each classification. If an email is not suspicious, state that explicitly. Always use formal language and ensure your responses are clear and actionable. If you cannot determine the status due to insufficient information, indicate that the analysis is inconclusive."
)
OUTPUT_FORMAT = (
    'Return a structured list where each email is classified as "phishing", "suspicious", or "not suspicious", along with a brief explanation for the classification.'
)
FALLBACK_RESPONSE = (
    "Unable to determine if the email is phishing or suspicious due to insufficient information."
)

VALIDATION_CONFIG_PATH = Config.VALIDATION_CONFIG_PATH or str(Path(__file__).parent / "validation_config.json")

logger = logging.getLogger("agent")
logger.setLevel(logging.INFO)

# =========================
# Input/Output Models
# =========================

class RawEmail(BaseModel):
    email_raw: str = Field(..., description="Raw RFC822 email string")

    @field_validator("email_raw")
    @classmethod
    def validate_email_raw(cls, v):
        if not v or not isinstance(v, str) or not v.strip():
            raise ValueError("Email content must be a non-empty string.")
        if len(v) > 50000:
            raise ValueError("Email content exceeds 50,000 character limit.")
        return v.strip()

class AnalyzeEmailsRequest(BaseModel):
    emails: List[RawEmail] = Field(..., description="List of raw emails to analyze (RFC822 format)")

    @field_validator("emails")
    @classmethod
    def validate_emails(cls, v):
        if not v or not isinstance(v, list) or len(v) == 0:
            raise ValueError("At least one email must be provided.")
        if len(v) > 50:
            raise ValueError("Maximum 50 emails per request.")
        return v

class ClassificationResult(BaseModel):
    classification: str = Field(..., description='One of "phishing", "suspicious", "not suspicious", or "inconclusive"')
    explanation: str = Field(..., description="Explanation for the classification")
    email_index: int = Field(..., description="Index of the email in the input list (0-based)")

class AnalyzeEmailsResponse(BaseModel):
    results: List[ClassificationResult] = Field(..., description="List of classification results")
    success: bool = Field(..., description="Whether the analysis was successful")
    error: Optional[str] = Field(None, description="Error message if any")

# =========================
# Utility: LLM Output Sanitizer
# =========================

import re as _re

_FENCE_RE = _re.compile(r"```(?:\w+)?\s*\n(.*?)```", _re.DOTALL)
_LONE_FENCE_START_RE = _re.compile(r"^```\w*$")
_WRAPPER_RE = _re.compile(
    r"^(?:"
    r"Here(?:'s| is)(?: the)? (?:the |your |a )?(?:code|solution|implementation|result|explanation|answer)[^:]*:\s*"
    r"|Sure[!,.]?\s*"
    r"|Certainly[!,.]?\s*"
    r"|Below is [^:]*:\s*"
    r")",
    _re.IGNORECASE,
)
_SIGNOFF_RE = _re.compile(
    r"^(?:Let me know|Feel free|Hope this|This code|Note:|Happy coding|If you)",
    _re.IGNORECASE,
)
_BLANK_COLLAPSE_RE = _re.compile(r"\n{3,}")

def _strip_fences(text: str, content_type: str) -> str:
    """Extract content from Markdown code fences."""
    fence_matches = _FENCE_RE.findall(text)
    if fence_matches:
        if content_type == "code":
            return "\n\n".join(block.strip() for block in fence_matches)
        for match in fence_matches:
            fenced_block = _FENCE_RE.search(text)
            if fenced_block:
                text = text[:fenced_block.start()] + match.strip() + text[fenced_block.end():]
        return text
    lines = text.splitlines()
    if lines and _LONE_FENCE_START_RE.match(lines[0].strip()):
        lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines).strip()

def _strip_trailing_signoffs(text: str) -> str:
    """Remove conversational sign-off lines from the end of code output."""
    lines = text.splitlines()
    while lines and _SIGNOFF_RE.match(lines[-1].strip()):
        lines.pop()
    return "\n".join(lines).rstrip()

@with_content_safety(config=GUARDRAILS_CONFIG)
def sanitize_llm_output(raw: str, content_type: str = "code") -> str:
    """
    Generic post-processor that cleans common LLM output artefacts.
    Args:
        raw: Raw text returned by the LLM.
        content_type: 'code' | 'text' | 'markdown'.
    Returns:
        Cleaned string ready for validation, formatting, or direct return.
    """
    if not raw:
        return ""
    text = _strip_fences(raw.strip(), content_type)
    text = _WRAPPER_RE.sub("", text, count=1).strip()
    if content_type == "code":
        text = _strip_trailing_signoffs(text)
    return _BLANK_COLLAPSE_RE.sub("\n\n", text).strip()

# =========================
# EmailIngestionService
# =========================

class EmailIngestionService:
    """
    Receives and parses incoming emails, extracts content and metadata.
    """

    def parse_email(self, email_raw: str) -> Dict[str, Any]:
        """
        Parses raw email input into content and metadata.
        Raises INVALID_EMAIL_FORMAT on failure.
        """
        try:
            # Parse using Python's email library (RFC822)
            msg = email.message_from_string(email_raw, policy=policy.default)
            content = ""
            if msg.is_multipart():
                for part in msg.walk():
                    ctype = part.get_content_type()
                    if ctype == "text/plain":
                        content += part.get_content()
            else:
                content = msg.get_content()
            metadata = {
                "from": msg.get("From"),
                "to": msg.get("To"),
                "subject": msg.get("Subject"),
                "date": msg.get("Date"),
                "reply_to": msg.get("Reply-To"),
                "message_id": msg.get("Message-ID"),
                "headers": dict(msg.items()),
            }
            return {
                "content": content.strip(),
                "metadata": metadata,
            }
        except Exception as e:
            raise ValueError("INVALID_EMAIL_FORMAT") from e

    def get_email_content(self, parsed_email: Dict[str, Any]) -> str:
        return parsed_email.get("content", "")

    def get_email_metadata(self, parsed_email: Dict[str, Any]) -> Dict[str, Any]:
        return parsed_email.get("metadata", {})

# =========================
# EmailAnalysisEngine
# =========================

class EmailAnalysisEngine:
    """
    Applies business rules to analyze email content and metadata, prepares input for LLM.
    """

    def __init__(self, audit_logger: "AuditLogger"):
        self.audit_logger = audit_logger

    @with_content_safety(config=GUARDRAILS_CONFIG)
    def analyze_email(self, email_content: str, email_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Applies phishing detection rules to parsed email.
        Returns a dict with rule evaluation results.
        """
        try:
            suspicion_reasons = []
            contains_suspicious_links = self._detect_suspicious_links(email_content)
            if contains_suspicious_links:
                suspicion_reasons.append("Suspicious link detected")
                self.audit_logger.log_event("RULE_TRIGGER", {
                    "rule_id": "R-001",
                    "reason": "Suspicious link detected"
                })

            contains_urgent_language = self._detect_urgent_language(email_content)
            if contains_urgent_language:
                suspicion_reasons.append("Urgent/threatening language detected")
                self.audit_logger.log_event("RULE_TRIGGER", {
                    "rule_id": "R-002",
                    "reason": "Urgent/threatening language detected"
                })

            sender_mismatch = self._detect_sender_mismatch(email_metadata)
            if sender_mismatch:
                suspicion_reasons.append("Sender mismatch detected")
                self.audit_logger.log_event("RULE_TRIGGER", {
                    "rule_id": "R-003",
                    "reason": "Sender mismatch detected"
                })

            return {
                "contains_suspicious_links": contains_suspicious_links,
                "contains_urgent_language": contains_urgent_language,
                "sender_mismatch": sender_mismatch,
                "suspicion_reasons": suspicion_reasons,
            }
        except Exception as e:
            self.audit_logger.log_event("ANALYSIS_FAILURE", {"error": str(e)})
            raise ValueError("ANALYSIS_FAILURE") from e

    def _detect_suspicious_links(self, content: str) -> bool:
        # Simple heuristic: look for http/https links with non-corporate domains or obfuscated URLs
        suspicious_link_pattern = re.compile(r"https?://[^\s]+", re.IGNORECASE)
        links = suspicious_link_pattern.findall(content or "")
        for link in links:
            # Heuristic: flag if link contains known suspicious patterns
            if any(s in link.lower() for s in ["login", "verify", "update", "secure", "account", "bank", "confirm", "reset"]):
                return True
            # Obfuscated links (e.g., IP address, hex, or non-standard TLDs)
            if re.search(r"https?://\d+\.\d+\.\d+\.\d+", link):
                return True
            if re.search(r"https?://[a-f0-9]{8,}", link):
                return True
        return False

    def _detect_urgent_language(self, content: str) -> bool:
        # Look for urgent/threatening phrases
        urgent_patterns = [
            r"immediately", r"urgent", r"as soon as possible", r"account locked",
            r"verify your account", r"suspend", r"action required", r"threat", r"final notice",
            r"your account will be closed", r"click here", r"reset your password"
        ]
        for pattern in urgent_patterns:
            if re.search(pattern, content or "", re.IGNORECASE):
                return True
        return False

    def _detect_sender_mismatch(self, metadata: Dict[str, Any]) -> bool:
        # Heuristic: if 'From' address does not match 'Reply-To' or domain mismatch
        from_addr = metadata.get("from", "") or ""
        reply_to = metadata.get("reply_to", "") or ""
        if from_addr and reply_to and from_addr != reply_to:
            return True
        # Check for suspicious domains (e.g., misspelled, free email providers)
        suspicious_domains = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"]
        for domain in suspicious_domains:
            if domain in from_addr.lower() and not any(domain in (reply_to or "").lower() for domain in suspicious_domains):
                return True
        return False

# =========================
# LLMService
# =========================

class LLMService:
    """
    Handles interaction with Azure OpenAI GPT-4.1, sends enhanced system prompt and email data, receives classification and explanation.
    """

    def __init__(self):
        self._client = None

    def _get_client(self):
        if self._client is not None:
            return self._client
        api_key = Config.AZURE_OPENAI_API_KEY
        if not api_key:
            raise ValueError("AZURE_OPENAI_API_KEY not configured")
        import openai
        self._client = openai.AsyncAzureOpenAI(
            api_key=api_key,
            api_version="2024-02-01",
            azure_endpoint=Config.AZURE_OPENAI_ENDPOINT,
        )
        return self._client

    async def classify_email(self, email_content: str, email_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calls LLM with enhanced system prompt and email data for classification.
        Retries on timeout or API error, returns fallback response if LLM fails.
        """
        client = self._get_client()
        model = Config.LLM_MODEL or "gpt-4.1"
        _llm_kwargs = Config.get_llm_kwargs()
        user_message = (
            f"Email Content:\n{email_content}\n\n"
            f"Email Metadata:\n{json.dumps(email_metadata, ensure_ascii=False, indent=2)}\n\n"
            "Classify this email as 'phishing', 'suspicious', or 'not suspicious'. "
            "Provide a brief explanation for your classification."
        )
        system_message = SYSTEM_PROMPT + "\n\nOutput Format: " + OUTPUT_FORMAT
        max_retries = 3
        for attempt in range(max_retries):
            _t0 = _time.time()
            try:
                response = await client.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system", "content": system_message},
                        {"role": "user", "content": user_message}
                    ],
                    **_llm_kwargs
                )
                content = response.choices[0].message.content
                try:
                    trace_model_call(
                        provider="azure",
                        model_name=model,
                        prompt_tokens=getattr(getattr(response, "usage", None), "prompt_tokens", 0) or 0,
                        completion_tokens=getattr(getattr(response, "usage", None), "completion_tokens", 0) or 0,
                        latency_ms=int((_time.time() - _t0) * 1000),
                        response_summary=content[:200] if content else "",
                    )
                except Exception:
                    pass
                return {
                    "raw_llm_response": content
                }
            except Exception as e:
                logger.warning(f"LLM call failed (attempt {attempt+1}): {e}")
                if attempt == max_retries - 1:
                    return {
                        "raw_llm_response": FALLBACK_RESPONSE
                    }
                await self._exponential_backoff(attempt)
        return {
            "raw_llm_response": FALLBACK_RESPONSE
        }

    async def _exponential_backoff(self, attempt: int):
        delay = min(2 ** attempt, 8)
        await self._async_sleep(delay)

    async def _async_sleep(self, seconds: int):
        await asyncio.sleep(seconds)

# =========================
# AuditLogger
# =========================

class AuditLogger:
    """
    Logs analysis events, rule triggers, and maintains audit trail for compliance.
    """

    def __init__(self):
        self.logger = logging.getLogger("audit_logger")
        self.logger.setLevel(logging.INFO)

    def log_event(self, event_type: str, details: Dict[str, Any]):
        """
        Logs analysis events and rule triggers for audit trail.
        Ensures logging does not block processing; logs to secondary store if primary fails.
        """
        try:
            self.logger.info(f"[{event_type}] {json.dumps(details, ensure_ascii=False)}")
        except Exception as e:
            try:
                # Fallback: log to file if main logger fails
                with open("audit_fallback.log", "a", encoding="utf-8") as f:
                    f.write(f"[{event_type}] {json.dumps(details, ensure_ascii=False)}\n")
            except Exception:
                pass

# =========================
# OutputFormatter
# =========================

class OutputFormatter:
    """
    Formats classification results and explanations into structured output.
    """

    def format_response(self, classification_results: List[Dict[str, Any]]) -> List[ClassificationResult]:
        """
        Formats classification results into structured output.
        Returns error template if formatting fails.
        """
        formatted = []
        for idx, result in enumerate(classification_results):
            classification = result.get("classification", "inconclusive")
            explanation = result.get("explanation", FALLBACK_RESPONSE)
            formatted.append(ClassificationResult(
                classification=classification,
                explanation=explanation,
                email_index=idx
            ))
        return formatted

# =========================
# Main Agent
# =========================

class EmailPhishingDetectionAgent:
    """
    Main agent orchestrating the end-to-end analysis of a batch of emails.
    """

    def __init__(self):
        self.ingestion_service = EmailIngestionService()
        self.audit_logger = AuditLogger()
        self.analysis_engine = EmailAnalysisEngine(self.audit_logger)
        self.llm_service = LLMService()
        self.output_formatter = OutputFormatter()
        self.guardrails_config = GUARDRAILS_CONFIG

    @with_content_safety(config=GUARDRAILS_CONFIG)
    async def analyze_emails(self, emails: List[RawEmail]) -> Dict[str, Any]:
        """
        Orchestrates the end-to-end analysis of a batch of emails.
        """
        results = []
        errors = []
        async with trace_step(
            "parse_and_analyze_emails",
            step_type="process",
            decision_summary="Parse, analyze, and classify emails",
            output_fn=lambda r: f"{len(r)} emails processed" if isinstance(r, list) else str(r),
        ) as step:
            for idx, raw_email in enumerate(emails):
                try:
                    # Parse email
                    parsed = self.ingestion_service.parse_email(raw_email.email_raw)
                    email_content = self.ingestion_service.get_email_content(parsed)
                    email_metadata = self.ingestion_service.get_email_metadata(parsed)
                    # Apply business rules
                    rule_eval = self.analysis_engine.analyze_email(email_content, email_metadata)
                    # Call LLM for classification
                    llm_result = await self.llm_service.classify_email(email_content, email_metadata)
                    raw_llm_response = llm_result.get("raw_llm_response", "")
                    sanitized = sanitize_llm_output(raw_llm_response, content_type="text")
                    # Parse LLM output for classification and explanation
                    classification, explanation = self._extract_classification_and_explanation(sanitized)
                    if not classification:
                        classification = "inconclusive"
                        explanation = FALLBACK_RESPONSE
                    results.append({
                        "classification": classification,
                        "explanation": explanation,
                        "email_index": idx
                    })
                except Exception as e:
                    self.audit_logger.log_event("PROCESSING_ERROR", {
                        "email_index": idx,
                        "error": str(e)
                    })
                    results.append({
                        "classification": "inconclusive",
                        "explanation": FALLBACK_RESPONSE,
                        "email_index": idx
                    })
                    errors.append({"email_index": idx, "error": str(e)})
            step.capture(results)
        formatted = self.output_formatter.format_response(results)
        return {
            "results": formatted,
            "success": True if not errors else False,
            "error": None if not errors else f"{len(errors)} email(s) failed to process"
        }

    def _extract_classification_and_explanation(self, llm_output: str) -> (str, str):
        """
        Attempts to extract classification and explanation from LLM output.
        """
        # Try to parse as JSON list or dict
        try:
            data = json.loads(llm_output)
            if isinstance(data, list) and data:
                entry = data[0]
                classification = entry.get("classification", "")
                explanation = entry.get("explanation", "")
                return classification, explanation
            elif isinstance(data, dict):
                classification = data.get("classification", "")
                explanation = data.get("explanation", "")
                return classification, explanation
        except Exception:
            pass
        # Fallback: regex extraction
        classification = ""
        explanation = ""
        class_match = re.search(r"Classification\s*:\s*(phishing|suspicious|not suspicious|inconclusive)", llm_output, re.IGNORECASE)
        if class_match:
            classification = class_match.group(1).lower()
        explanation_match = re.search(r"Explanation\s*:\s*(.+)", llm_output, re.IGNORECASE)
        if explanation_match:
            explanation = explanation_match.group(1).strip()
        if not classification:
            # Try to infer from text
            if "phishing" in llm_output.lower():
                classification = "phishing"
            elif "suspicious" in llm_output.lower():
                classification = "suspicious"
            elif "not suspicious" in llm_output.lower():
                classification = "not suspicious"
            else:
                classification = "inconclusive"
        if not explanation:
            explanation = llm_output.strip()
        return classification, explanation

# =========================
# FastAPI App & Endpoints
# =========================

@asynccontextmanager
async def _obs_lifespan(application):
    """Initialise observability on startup, clean up on shutdown."""
    try:
        _obs_startup_logger.info('')
        _obs_startup_logger.info('========== Agent Configuration Summary ==========')
        _obs_startup_logger.info(f'Environment: {getattr(Config, "ENVIRONMENT", "N/A")}')
        _obs_startup_logger.info(f'Agent: {getattr(Config, "AGENT_NAME", "N/A")}')
        _obs_startup_logger.info(f'Project: {getattr(Config, "PROJECT_NAME", "N/A")}')
        _obs_startup_logger.info(f'LLM Provider: {getattr(Config, "MODEL_PROVIDER", "N/A")}')
        _obs_startup_logger.info(f'LLM Model: {getattr(Config, "LLM_MODEL", "N/A")}')
        _cs_endpoint = getattr(Config, 'AZURE_CONTENT_SAFETY_ENDPOINT', None)
        _cs_key = getattr(Config, 'AZURE_CONTENT_SAFETY_KEY', None)
        if _cs_endpoint and _cs_key:
            _obs_startup_logger.info('Content Safety: Enabled (Azure Content Safety)')
            _obs_startup_logger.info(f'Content Safety Endpoint: {_cs_endpoint}')
        else:
            _obs_startup_logger.info('Content Safety: Not Configured')
        _obs_startup_logger.info('Observability Database: Azure SQL')
        _obs_startup_logger.info(f'Database Server: {getattr(Config, "OBS_AZURE_SQL_SERVER", "N/A")}')
        _obs_startup_logger.info(f'Database Name: {getattr(Config, "OBS_AZURE_SQL_DATABASE", "N/A")}')
        _obs_startup_logger.info('===============================================')
        _obs_startup_logger.info('')
    except Exception as _e:
        _obs_startup_logger.warning('Config summary failed: %s', _e)

    _obs_startup_logger.info('')
    _obs_startup_logger.info('========== Content Safety & Guardrails ==========')
    if GUARDRAILS_CONFIG.get('content_safety_enabled'):
        _obs_startup_logger.info('Content Safety: Enabled')
        _obs_startup_logger.info(f'  - Severity Threshold: {GUARDRAILS_CONFIG.get("content_safety_severity_threshold", "N/A")}')
        _obs_startup_logger.info(f'  - Check Toxicity: {GUARDRAILS_CONFIG.get("check_toxicity", False)}')
        _obs_startup_logger.info(f'  - Check Jailbreak: {GUARDRAILS_CONFIG.get("check_jailbreak", False)}')
        _obs_startup_logger.info(f'  - Check PII Input: {GUARDRAILS_CONFIG.get("check_pii_input", False)}')
        _obs_startup_logger.info(f'  - Check Credentials Output: {GUARDRAILS_CONFIG.get("check_credentials_output", False)}')
    else:
        _obs_startup_logger.info('Content Safety: Disabled')
    _obs_startup_logger.info('===============================================')
    _obs_startup_logger.info('')

    _obs_startup_logger.info('========== Initializing Agent Services ==========')
    # 1. Observability DB schema (imports are inside function — only needed at startup)
    try:
        from observability.database.engine import create_obs_database_engine
        from observability.database.base import ObsBase
        import observability.database.models  # noqa: F401
        _obs_engine = create_obs_database_engine()
        ObsBase.metadata.create_all(bind=_obs_engine, checkfirst=True)
        _obs_startup_logger.info('✓ Observability database connected')
    except Exception as _e:
        _obs_startup_logger.warning('✗ Observability database connection failed (metrics will not be saved)')
    # 2. OpenTelemetry tracer (initialize_tracer is pre-injected at top level)
    try:
        _t = initialize_tracer()
        if _t is not None:
            _obs_startup_logger.info('✓ Telemetry monitoring enabled')
        else:
            _obs_startup_logger.warning('✗ Telemetry monitoring disabled')
    except Exception as _e:
        _obs_startup_logger.warning('✗ Telemetry monitoring failed to initialize')
    _obs_startup_logger.info('=================================================')
    _obs_startup_logger.info('')
    yield

app = FastAPI(
    title="Email Phishing Detection Agent",
    description="Detects phishing and suspicious emails using Azure OpenAI GPT-4.1 and business rules.",
    version=Config.SERVICE_VERSION if hasattr(Config, "SERVICE_VERSION") else "1.0.0",
    lifespan=_obs_lifespan
)

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok"}

@app.exception_handler(ValidationError)
@with_content_safety(config=GUARDRAILS_CONFIG)
async def validation_exception_handler(request: Request, exc: ValidationError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "success": False,
            "error": "Input validation error",
            "details": exc.errors(),
            "tips": [
                "Ensure your JSON is well-formed.",
                "Check for missing or extra commas, brackets, or quotes.",
                "Each email must be a valid RFC822 string and under 50,000 characters.",
                "Maximum 50 emails per request."
            ]
        }
    )

@app.exception_handler(json.decoder.JSONDecodeError)
@with_content_safety(config=GUARDRAILS_CONFIG)
async def json_decode_exception_handler(request: Request, exc: json.decoder.JSONDecodeError):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "success": False,
            "error": "Malformed JSON in request body",
            "details": str(exc),
            "tips": [
                "Check for missing or extra commas, brackets, or quotes.",
                "Ensure your JSON is well-formed and matches the API schema."
            ]
        }
    )

@app.post("/analyze", response_model=AnalyzeEmailsResponse)
@with_content_safety(config=GUARDRAILS_CONFIG)
async def analyze_emails_endpoint(req: AnalyzeEmailsRequest):
    """
    Analyze a batch of emails for phishing or suspicious content.
    """
    agent = EmailPhishingDetectionAgent()
    try:
        async with trace_step(
            "analyze_emails_endpoint",
            step_type="process",
            decision_summary="Endpoint entry for email analysis",
            output_fn=lambda r: f"{len(r['results'])} emails analyzed" if isinstance(r, dict) and 'results' in r else str(r),
        ) as step:
            result = await agent.analyze_emails(req.emails)
            step.capture(result)
        # Sanitize LLM output in all explanations
        for res in result["results"]:
            res.explanation = sanitize_llm_output(res.explanation, content_type="text")
        return AnalyzeEmailsResponse(
            results=result["results"],
            success=result.get("success", True),
            error=result.get("error")
        )
    except Exception as e:
        logger.error(f"Error in analyze_emails_endpoint: {e}", exc_info=True)
        return AnalyzeEmailsResponse(
            results=[],
            success=False,
            error=f"Failed to process emails: {str(e)}"
        )

# =========================
# Entrypoint
# =========================

async def _run_agent():
    """Entrypoint: runs the agent with observability (trace collection only)."""
    import uvicorn

    # Unified logging config — routes uvicorn, agent, and observability through
    # the same handler so all telemetry appears in a single consistent stream.
    _LOG_CONFIG = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "default": {
                "()": "uvicorn.logging.DefaultFormatter",
                "fmt": "%(levelprefix)s %(name)s: %(message)s",
                "use_colors": None,
            },
            "access": {
                "()": "uvicorn.logging.AccessFormatter",
                "fmt": '%(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s',
            },
        },
        "handlers": {
            "default": {
                "formatter": "default",
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stderr",
            },
            "access": {
                "formatter": "access",
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stdout",
            },
        },
        "loggers": {
            "uvicorn":        {"handlers": ["default"], "level": "INFO", "propagate": False},
            "uvicorn.error":  {"level": "INFO"},
            "uvicorn.access": {"handlers": ["access"], "level": "INFO", "propagate": False},
            "agent":          {"handlers": ["default"], "level": "INFO", "propagate": False},
            "__main__":       {"handlers": ["default"], "level": "INFO", "propagate": False},
            "observability": {"handlers": ["default"], "level": "INFO", "propagate": False},
            "config": {"handlers": ["default"], "level": "INFO", "propagate": False},
            "azure":   {"handlers": ["default"], "level": "WARNING", "propagate": False},
            "urllib3": {"handlers": ["default"], "level": "WARNING", "propagate": False},
        },
    }

    config = uvicorn.Config(
        "agent:app",
        host="0.0.0.0",
        port=8080,
        reload=False,
        log_level="info",
        log_config=_LOG_CONFIG,
    )
    server = uvicorn.Server(config)
    await server.serve()


if __name__ == "__main__":
    _asyncio.run(_run_agent())