
import pytest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
from agent import EmailPhishingDetectionAgent, RawEmail, ClassificationResult, AnalyzeEmailsResponse

@pytest.mark.asyncio
async def test_analyze_single_email_functional_classification():
    """
    Validates that EmailPhishingDetectionAgent.analyze_emails correctly classifies a single valid email
    and returns structured output.
    """
    # Prepare a valid RFC822 email string (non-phishing content)
    valid_email = (
        "From: alice@example.com\n"
        "To: bob@example.com\n"
        "Subject: Meeting Reminder\n"
        "Date: Fri, 1 Mar 2024 10:00:00 +0000\n"
        "\n"
        "Hi Bob,\n\nJust a reminder about our meeting next week.\n\nBest,\nAlice"
    )
    raw_email = RawEmail(email_raw=valid_email)
    emails = [raw_email]

    # Patch LLMService.classify_email to return a deterministic, non-phishing response
    fake_llm_response = {
        "raw_llm_response": '{"classification": "not suspicious", "explanation": "This email is a standard meeting reminder with no suspicious content."}'
    }
    with patch("agent.LLMService.classify_email", new_callable=AsyncMock) as mock_classify_email:
        mock_classify_email.return_value = fake_llm_response

        # Patch sanitize_llm_output to be identity (no-op) for simplicity
        with patch("agent.sanitize_llm_output", side_effect=lambda x, content_type="text": x):
            agent = EmailPhishingDetectionAgent()
            result = await agent.analyze_emails(emails)

    # The agent returns a dict, but the endpoint wraps it in AnalyzeEmailsResponse
    # We'll check the dict structure as returned by analyze_emails
    assert result is not None
    assert result.get("success") is True
    assert isinstance(result.get("results"), list)
    assert len(result["results"]) == 1
    res0 = result["results"][0]
    assert isinstance(res0, ClassificationResult)
    assert res0.classification in ["phishing", "suspicious", "not suspicious", "inconclusive"]
    assert isinstance(res0.explanation, str)