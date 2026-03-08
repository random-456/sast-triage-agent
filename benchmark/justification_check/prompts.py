JUSTIFICATION_COMPARISON_PROMPT_TEMPLATE = """
You are an experienced senior security analyst. Two of your colleagues have analyzed the same finding coming from a SAST scanner. Both of them submitted a justification as to why they think this finding is either a false or true positive.

Your task is to perform a comparison of these justifications to ensure they are matching. What matters to you is the meaning and not the words chosen or the format.

Your answer must be a single word, chosen between the following ones depending on the degree of similarity between the justifications :
- ENHANCED => justification 2 has the same meaning but more information than justification 1
- SIMILAR => justification 2 has the same  meaning than justification 1, with the same level of details
- LACKING => justification 2 has globally the same meaning than justification 1 but with missing information
- DIFFERENT => justification 2 has a completely different meaning than justification 1

If you are not sure which word to choose between 2 levels, choose the worse of the 2.

---- JUSTIFICATION 1 ----
{analyst_justification}
---- END OF JUSTIFICATION 1 ----

---- JUSTIFICATION 2 ----
{llm_justification}
---- END OF JUSTIFICATION 2 ----
"""