import logging
import traceback

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

from benchmark.justification_check.prompts import JUSTIFICATION_COMPARISON_PROMPT_TEMPLATE
from config import DEFAULT_JUSTIFICATION_COMPARISON_MODEL

logger = logging.getLogger(__name__)

class JustificationAICheck:

    def __init__(
        self,
        project: str | None,
        location: str | None,
        temperature: float = 0.1
    ):
        """
        Initialize the JustificationAICheck object.

        Args:
            project: GCP project ID for Vertex AI, or None for AI Studio
            location: Vertex AI region (used only when project is set)
            temperature: Model temperature for consistency
        """
        common = dict(
            model=DEFAULT_JUSTIFICATION_COMPARISON_MODEL,
            temperature=temperature,
            max_retries=3,
        )
        if project:
            self.llm = ChatGoogleGenerativeAI(
                vertexai=True,
                project=project,
                location=location,
                **common,
            )
        else:
            self.llm = ChatGoogleGenerativeAI(**common)

        self.prompt_template = ChatPromptTemplate.from_template(JUSTIFICATION_COMPARISON_PROMPT_TEMPLATE)

    def compare_justifications(self, analyst_justification: str, llm_justification: str) -> str | None:
        try:
            chain = self.prompt_template | self.llm | StrOutputParser()

            logger.debug("Comparing justifications...")

            response = chain.invoke({
                "analyst_justification": analyst_justification,
                "llm_justification": llm_justification
            })

            logger.debug(f"Comparison result: {response}")
            return response

        except Exception:
            logger.error("Failed to compare justifications")
            logger.error(traceback.format_exc())
            return None