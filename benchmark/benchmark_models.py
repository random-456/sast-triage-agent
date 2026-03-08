from pydantic import BaseModel
from typing import List
from enum import Enum

# Models required for benchmarking

class JustificationComparisonResult(Enum):
  ENHANCED = 4
  SIMILAR = 3
  LACKING = 2
  DIFFERENT = 1

class Language(Enum):
  JAVA = "Java"
  JAVASCRIPT = "Javascript"
  ANGULAR = "Angular"
  NODEJS = "NodeJS"
  PYTHON = "Python"
  PHP = "PHP"
  C = "C"
  CPP = "C++"
  KOTLIN = "Kotlin"
  SWIFT = "Swift"
  DOTNET = ".NET"
  CSHARP = "C#"

class Severity(Enum):
  CRITICAL = "CRITICAL"
  HIGH = "HIGH"
  MEDIUM = "MEDIUM"
  LOW = "LOW"
  INFO = "INFO"

class Complexity(Enum):
  COMPLEX = "COMPLEX"
  MEDIUM = "MEDIUM"
  EASY = "EASY"

class TriageResult(Enum):
  CONFIRMED = "CONFIRMED"
  NOT_EXPLOITABLE = "NOT_EXPLOITABLE"
  REFUSED = "REFUSED"

class DatasetTriage(BaseModel):
  result: TriageResult
  justification: str

class DatasetFinding(BaseModel):
  id: str
  language: Language
  category: str
  severity: Severity
  complexity: Complexity
  analyst_triage: DatasetTriage

class DatasetProject(BaseModel):
  project: str
  github_url: str
  findings: List[DatasetFinding]