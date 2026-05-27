import logging
import traceback

from langchain_google_vertexai import ChatVertexAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

from benchmark.justification_check.prompts import JUSTIFICATION_COMPARISON_PROMPT_TEMPLATE
from config import DEFAULT_JUSTIFICATION_COMPARISON_MODEL

logger = logging.getLogger(__name__)

class JustificationAICheck:

    def __init__(
        self,
        project: str,
        location: str,
        temperature: float = 0.1
    ):
        """
        Initialize the JustificationAICheck object.

        Args:
            project: GCP project ID for Vertex AI.
            location: Vertex AI region.
            temperature: Model temperature for consistency.
        """
        self.llm = ChatVertexAI(
            model_name=DEFAULT_JUSTIFICATION_COMPARISON_MODEL,
            project=project,
            location=location,
            temperature=temperature,
            max_retries=3,
        )

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