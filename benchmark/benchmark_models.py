from pydantic import BaseModel
from typing import List, Optional
from enum import Enum

# Models required for benchmarking

class JustificationComparisonResult(Enum):
  ENHANCED = 4
  SIMILAR = 3
  LACKING = 2
  DIFFERENT = 1

class Language(Enum):
  JAVA = "java"
  JAVASCRIPT = "javascript"
  ANGULAR = "angular"
  NODEJS = "nodejs"
  PYTHON = "python"
  PHP = "php"
  C = "c"
  CPP = "c++"
  KOTLIN = "kotlin"
  SWIFT = "swift"
  DOTNET = ".net"
  CSHARP = "c#"

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
  complexity: Optional[Complexity] = None
  analyst_triage: DatasetTriage

class DatasetProject(BaseModel):
  project: str
  github_url: str
  findings: List[DatasetFinding]