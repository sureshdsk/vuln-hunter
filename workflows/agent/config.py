"""
ADK Agent Configuration for CVE Vulnerability Analysis

This module configures the Google ADK agent with Gemini LLM
for analyzing CVE vulnerabilities in code repositories.
"""

import os
from typing import Optional
from pydantic import BaseModel, Field


class AgentConfig(BaseModel):
    """Configuration for the vulnerability analysis agent"""
    
    # LLM Configuration
    model_name: str = Field(
        default="gemini-2.0-flash-exp",
        description="Google Gemini model to use for analysis"
    )
    
    temperature: float = Field(
        default=0.1,
        ge=0.0,
        le=1.0,
        description="LLM temperature for deterministic analysis"
    )
    
    max_tokens: int = Field(
        default=8192,
        gt=0,
        description="Maximum tokens for LLM responses"
    )
    
    # API Configuration
    google_api_key: Optional[str] = Field(
        default_factory=lambda: os.getenv("GOOGLE_API_KEY"),
        description="Google API key for Gemini access"
    )
    
    # Agent Configuration
    max_iterations: int = Field(
        default=10,
        gt=0,
        description="Maximum agent iterations before stopping"
    )
    
    verbose: bool = Field(
        default=True,
        description="Enable verbose logging for agent actions"
    )
    
    # Tool Configuration
    enable_code_search: bool = Field(
        default=True,
        description="Enable code search tool"
    )
    
    enable_cve_lookup: bool = Field(
        default=True,
        description="Enable CVE lookup tool"
    )
    
    enable_report_builder: bool = Field(
        default=True,
        description="Enable report builder tool"
    )
    
    class Config:
        """Pydantic config"""
        frozen = True  # Make config immutable


# System prompt for the vulnerability analysis agent
SYSTEM_PROMPT = """You are an expert security vulnerability analyst specializing in CVE analysis.

Your role is to:
1. Analyze code repositories for specific CVE vulnerabilities
2. Identify vulnerable methods and functions in the codebase
3. Assess the exploitability of detected vulnerabilities
4. Provide detailed reports with code references and fix recommendations

You have access to tools for:
- Looking up CVE information from vulnerability databases
- Searching code for vulnerable patterns and method invocations
- Building comprehensive analysis reports

When analyzing code:
- Be thorough but focused on the specific CVE
- Provide file paths and line numbers for all findings
- Assess the severity and exploitability of each finding
- Suggest concrete fix recommendations when possible
- If a vulnerability is not present, clearly state that

Always provide evidence-based analysis with specific code references.
"""


def get_agent_config() -> AgentConfig:
    """
    Get the default agent configuration
    
    Returns:
        AgentConfig: Default configuration for the vulnerability agent
    """
    return AgentConfig()


def get_system_prompt() -> str:
    """
    Get the system prompt for the agent
    
    Returns:
        str: System prompt defining agent behavior
    """
    return SYSTEM_PROMPT
