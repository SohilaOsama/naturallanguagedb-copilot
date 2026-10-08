from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import pandas as pd
import streamlit as st
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv(override=False)

try:
    import oracledb
except Exception:  # pragma: no cover
    oracledb = None


# ============================================================
# Core configuration
# ============================================================
@dataclass(frozen=True)
class OracleConfig:
    user: str = os.getenv("DB_USER", "")
    password: str = os.getenv("DB_PASSWORD", "")
    dsn: str = os.getenv("ECOMMERCE_ORACLE_DSN", "")
    default_schema: str = os.getenv("DEFAULT_SCHEMA", "ECOMMERCE").upper()
    max_rows: int = int(os.getenv("DEFAULT_MAX_SQL_ROWS", "10000"))


@dataclass(frozen=True)
class ModelConfig:
    provider: str = os.getenv("AI_PROVIDER", "ollama").lower()
    base_url: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1") if os.getenv("AI_PROVIDER", "ollama").lower() == "ollama" else os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
    model: str = os.getenv("OLLAMA_MODEL", "granite4.1:3b") if os.getenv("AI_PROVIDER", "ollama").lower() == "ollama" else os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    api_key: str = os.getenv("OPENAI_API_KEY", "") if os.getenv("AI_PROVIDER", "ollama").lower() != "ollama" else "no-key"
    temperature: float = float(os.getenv("AI_TEMPERATURE", "0.05"))
    max_tokens: int = int(os.getenv("AI_MAX_TOKENS", "2048"))


oracle_cfg = OracleConfig()
model_cfg = ModelConfig()


# ============================================================
# Security / auditing
# ============================================================
class PromptInjectionGuard:
    BLOCK_PATTERNS = [
        "ignore previous instructions",
        "system prompt",
        "override instructions",
        "bypass security",
        "pretend you are",
        "act as admin",
        "reveal secret",
    ]

    @staticmethod
    def sanitize(question: str) -> str:
        q = (question or "").strip()
        lowered = q.lower()
        for pattern in PromptInjectionGuard.BLOCK_PATTERNS:
            if pattern in lowered:
                raise ValueError(f"Potential prompt injection pattern detected: {pattern}")
        return q


class AuditLogger:
    def __init__(self, log_path: str = "logs/cim_agent_audit.log"):
        self.log_path = log_path
        os.makedirs(os.path.dirname(self.log_path) or ".", exist_ok=True)

    def write(self, event: Dict[str, Any]) -> None:
        payload = {"timestamp": __import__("datetime").datetime.utcnow().isoformat() + "Z", **event}
        with open(self.log_path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, default=str) + "\n")


audit_logger = AuditLogger()


# ============================================================
# Oracle schema discovery
# ============================================================
class OracleDiscoveryService:
    def __init__(self, config: OracleConfig):
        self.config = config
        self.connection = None

    def connect(self):
        if oracledb is None:
            raise RuntimeError("oracledb is not installed. Run: pip install oracledb")
        if not self.config.user or not self.config.password or not self.config.dsn:
            raise ValueError("Missing Oracle DB connection settings. Check DB_USER, DB_PASSWORD, and ECOMMERCE_ORACLE_DSN.")
        self.connection = oracledb.connect(user=self.config.user, password=self.config.password, dsn=self.config.dsn)
        return self.connection

    def _fetch_all(self, query: str, params: Optional[Dict[str, Any]] = None):
        if self.connection is None:
            self.connect()
        cursor = self.connection.cursor()
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        columns = [col[0] for col in cursor.description]
        rows = cursor.fetchall()
        return columns, rows

    def discover_schemas(self) -> List[str]:
        query = "SELECT username FROM all_users ORDER BY username"
        columns, rows = self._fetch_all(query)
        return [str(row[0]) for row in rows if row and row[0]]

    def discover_schema_catalog(self, schema_name: Optional[str] = None) -> Dict[str, Any]:
        schema_name = (schema_name or self.config.default_schema).upper()
        table_query = """
            SELECT table_name, tablespace_name, num_rows
            FROM all_tables
            WHERE owner = :owner
            ORDER BY table_name
        """
        columns_query = """
            SELECT table_name, column_name, data_type, data_length, nullable
            FROM all_tab_columns
            WHERE owner = :owner
            ORDER BY table_name, column_id
        """
        trig_query = """
            SELECT trigger_name, table_name, status, trigger_type
            FROM all_triggers
            WHERE owner = :owner
            ORDER BY trigger_name
        """
        proc_query = """
            SELECT object_name, object_type, status
            FROM all_objects
            WHERE owner = :owner
              AND object_type IN ('PROCEDURE', 'FUNCTION', 'PACKAGE', 'TYPE')
            ORDER BY object_type, object_name
        """

        _, tables = self._fetch_all(table_query, {"owner": schema_name})
        _, columns = self._fetch_all(columns_query, {"owner": schema_name})
        _, triggers = self._fetch_all(trig_query, {"owner": schema_name})
        _, procs = self._fetch_all(proc_query, {"owner": schema_name})

        table_list = [
            {"table_name": str(r[0]), "tablespace_name": str(r[1] or ""), "num_rows": r[2] if r[2] is not None else "unknown"}
            for r in tables
        ]
        column_map: Dict[str, List[Dict[str, Any]]] = {}
        for row in columns:
            table_name = str(row[0])
            column_map.setdefault(table_name, []).append({
                "column_name": str(row[1]),
                "data_type": str(row[2]),
                "data_length": row[3],
                "nullable": str(row[4]),
            })

        trigger_list = [
            {"trigger_name": str(r[0]), "table_name": str(r[1]), "status": str(r[2]), "trigger_type": str(r[3] or "")}
            for r in triggers
        ]
        proc_list = [
            {"object_name": str(r[0]), "object_type": str(r[1]), "status": str(r[2])}
            for r in procs
        ]

        return {
            "schema": schema_name,
            "table_count": len(table_list),
            "tables": table_list,
            "columns": column_map,
            "triggers": trigger_list,
            "procedures": proc_list,
        }

    def find_tables(self, keyword: str) -> List[str]:
        kw = (keyword or "").strip().upper()
        if not kw:
            return []
        query = """
            SELECT table_name
            FROM all_tables
            WHERE owner = :owner
              AND UPPER(table_name) LIKE :keyword
            ORDER BY table_name
        """
        _, rows = self._fetch_all(query, {"owner": self.config.default_schema, "keyword": f"%{kw}%"})
        return [str(r[0]) for r in rows]

    def describe_table(self, table_name: str) -> List[Dict[str, Any]]:
        query = """
            SELECT column_name, data_type, data_length, nullable
            FROM all_tab_columns
            WHERE owner = :owner AND table_name = :table_name
            ORDER BY column_id
        """
        _, rows = self._fetch_all(query, {"owner": self.config.default_schema, "table_name": table_name.upper()})
        return [
            {"column_name": str(r[0]), "data_type": str(r[1]), "data_length": r[2], "nullable": str(r[3])}
            for r in rows
        ]

    def execute_select(self, sql: str, max_rows: Optional[int] = None) -> Dict[str, Any]:
        safe_sql = sanitize_sql(sql)
        ok, severity, reason = validate_sql(safe_sql)
        if not ok:
            raise ValueError(f"SQL rejected by guard: {reason}")
        if max_rows is None:
            max_rows = self.config.max_rows
        if "FETCH FIRST" not in safe_sql.upper() and "ROWNUM" not in safe_sql.upper():
            safe_sql = f"{safe_sql} FETCH FIRST {max_rows} ROWS ONLY"
        cursor = self.connection.cursor()
        cursor.execute(safe_sql)
        columns = [d[0] for d in cursor.description]
        rows = cursor.fetchmany(max_rows)
        df = pd.DataFrame(rows, columns=columns)
        return {
            "columns": columns,
            "rows": df.to_dict(orient="records"),
            "row_count": len(df),
            "sql": safe_sql,
        }


# ============================================================
# SQL validation
# ============================================================
DANGEROUS_KEYWORDS = [
    "DROP", "TRUNCATE", "DELETE", "UPDATE", "INSERT", "ALTER", "GRANT", "REVOKE",
    "MERGE", "CREATE", "EXECUTE", "CALL", "COMMIT", "ROLLBACK", "BEGIN", "END",
    "DBMS_", "SYS.", "INJECTION", "SCHEDULER", "AUDIT",
]


def sanitize_sql(sql: str) -> str:
    if not sql:
        return ""
    cleaned = sql.strip().rstrip(";")
    cleaned = re.sub(r"/\*.*?\*/", " ", cleaned, flags=re.DOTALL)
    cleaned = re.sub(r"--.*?$", "", cleaned, flags=re.MULTILINE)
    return cleaned.strip()


def validate_sql(sql: str) -> tuple[bool, str, str]:
    clean_sql = sanitize_sql(sql)
    if not clean_sql:
        return False, "CRITICAL", "Empty SQL statement."
    upper = clean_sql.upper()
    if re.search(r";\s*(?:SELECT|WITH)", upper):
        return False, "CRITICAL", "Multiple statements or chained queries are not allowed."
    if "SELECT *" in upper:
        return False, "MEDIUM", "SELECT * is discouraged. Prefer explicit columns."
    for keyword in DANGEROUS_KEYWORDS:
        if re.search(rf"\b{re.escape(keyword)}\b", upper):
            return False, "CRITICAL", f"Disallowed SQL keyword detected: {keyword}"
    if not upper.startswith("SELECT") and not upper.startswith("WITH "):
        return False, "CRITICAL", "Only SELECT or CTE queries are allowed."
    return True, "LOW", "SQL validation passed."


def classify_query_risk(sql: str) -> str:
    upper = sanitize_sql(sql).upper()
    if "SELECT *" in upper:
        return "MEDIUM"
    if "JOIN" in upper and "WHERE" in upper:
        return "MEDIUM"
    if "GROUP BY" in upper or "ORDER BY" in upper:
        return "MEDIUM"
    return "LOW"


# ============================================================
# LLM integration (OpenAI-compatible Ollama / OpenAI)
# ============================================================
def build_llm_client(provider: str, base_url: str, api_key: str):
    if provider == "ollama":
        return OpenAI(api_key=api_key or "no-key", base_url=base_url)
    return OpenAI(api_key=api_key, base_url=base_url)


def ask_llm(question: str, schema_context: str, role: str = "ANALYST") -> str:
    provider = model_cfg.provider.lower()
    base_url = model_cfg.base_url
    api_key = model_cfg.api_key
    client = build_llm_client(provider, base_url, api_key)

    system_prompt = """
You are CIM Agent, a professional enterprise Oracle investigation copilot.
Your task is to answer database questions with evidence, explain the likely cause, and propose safe next steps.
Use the schema metadata provided. Do not invent tables, columns, or data.
If a query cannot be answered confidently, say so and ask for a more specific table or column.
Always keep answers operational, concise, and evidence-based.
"""

    response = client.chat.completions.create(
        model=model_cfg.model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Role: {role}\nUser question: {question}\n\nSchema context:\n{schema_context}"},
        ],
        temperature=model_cfg.temperature,
        max_tokens=model_cfg.max_tokens,
    )
    return response.choices[0].message.content.strip()


# ============================================================
# Schema-backed intent / SQL planning
# ============================================================
def build_schema_summary(catalog: Dict[str, Any]) -> str:
    lines = [f"SCHEMA: {catalog.get('schema', 'UNKNOWN')}\n"]
    for table in catalog.get("tables", [])[:25]:
        table_name = table["table_name"]
        cols = catalog.get("columns", {}).get(table_name, [])[:8]
        col_names = ", ".join(c["column_name"] for c in cols)
        lines.append(f"- {table_name}: {col_names}")
    return "\n".join(lines)


def guess_sql_from_question(question: str, catalog: Dict[str, Any]) -> str:
    q = question.strip().lower()
    tables = catalog.get("tables", [])
    table_names = [t["table_name"] for t in tables]

    # keyword -> likely table match
    candidates = []
    for table in table_names:
        table_l = table.lower()
        if re.search(r"order|payment|customer|voucher|invoice|session|incident|ticket|product|user|account", table_l) and any(token in q for token in table_l.split("_")):
            candidates.append(table)
    if not candidates:
        for table in table_names:
            table_l = table.lower()
            if any(token in q for token in [table_l[:3], table_l[-3:]]):
                candidates.append(table)

    chosen_table = candidates[0] if candidates else (table_names[0] if table_names else "DUAL")

    columns = catalog.get("columns", {}).get(chosen_table, [])
    key_cols = [c["column_name"] for c in columns if any(k in c["column_name"].lower() for k in ["id", "code", "status", "date", "created", "updated"])][:6]
    if not key_cols:
        key_cols = [c["column_name"] for c in columns[:6]]
    select_cols = ", ".join(key_cols)
    sql = f"SELECT {select_cols} FROM {chosen_table} FETCH FIRST 50 ROWS ONLY"
    return sql


# ============================================================
# Streamlit app
# ============================================================
st.set_page_config(page_title="CIM Agent", page_icon="🧠", layout="wide")


if "catalog" not in st.session_state:
    st.session_state.catalog = {}
if "schema_loaded" not in st.session_state:
    st.session_state.schema_loaded = False


@st.cache_data(show_spinner=False)
def discover_oracle_catalog() -> Dict[str, Any]:
    service = OracleDiscoveryService(oracle_cfg)
    service.connect()
    schema = service.discover_schema_catalog(oracle_cfg.default_schema)
    return schema


st.title("CIM Agent")
st.caption("Enterprise Oracle Schema Intelligence, SQL Safety, and AI-Assisted Investigation")

st.sidebar.title("Configuration")
st.sidebar.caption("Production Oracle environment")

provider = st.sidebar.selectbox("AI provider", ["ollama", "openai"], index=0 if model_cfg.provider == "ollama" else 1)
model_cfg_provider = provider

if provider == "ollama":
    model = st.sidebar.text_input("Ollama model", value=os.getenv("OLLAMA_MODEL", "granite4.1:3b"))
    base_url = st.sidebar.text_input("Ollama base URL", value=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1"))
    api_key = "no-key"
else:
    model = st.sidebar.text_input("OpenAI model", value=os.getenv("OPENAI_MODEL", "gpt-4o-mini"))
    base_url = st.sidebar.text_input("OpenAI base URL", value=os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"))
    api_key = st.sidebar.text_input("OpenAI API Key", value=os.getenv("OPENAI_API_KEY", ""), type="password")

schema_name = st.sidebar.text_input("Schema to inspect", value=oracle_cfg.default_schema)

with st.sidebar.expander("Database connection"):
    st.write(f"User: {oracle_cfg.user}")
    st.write(f"DSN: {oracle_cfg.dsn}")

if st.sidebar.button("Load schema catalog"):
    try:
        service = OracleDiscoveryService(oracle_cfg)
        service.connect()
        catalog = service.discover_schema_catalog(schema_name)
        st.session_state.catalog = catalog
        st.session_state.schema_loaded = True
        st.success(f"Loaded schema catalog for {schema_name}.")
        audit_logger.write({"event": "schema_loaded", "schema": schema_name, "table_count": catalog.get("table_count", 0)})
    except Exception as exc:
        st.error(f"Could not load schema: {exc}")
        audit_logger.write({"event": "schema_load_failed", "schema": schema_name, "error": str(exc)})

if st.session_state.schema_loaded:
    catalog = st.session_state.catalog
    st.subheader("Schema summary")
    st.write(f"Schema: {catalog.get('schema', 'unknown')}")
    st.write(f"Tables discovered: {catalog.get('table_count', 0)}")

    table_names = [t["table_name"] for t in catalog.get("tables", [])[:20]]
    st.dataframe(pd.DataFrame({"table_name": table_names}), use_container_width=True)

    with st.expander("View table metadata"):
        for table in catalog.get("tables", [])[:10]:
            name = table["table_name"]
            cols = catalog.get("columns", {}).get(name, [])
            st.markdown(f"### {name}")
            st.json(cols[:10])

question = st.text_area(
    "Ask CIM Agent",
    value="Why are the recent failed transactions appearing in the payment flow?",
    height=140,
    placeholder="Examples: Why is order 123456 failing? Show latest payments with status failed. Find customer by phone number.",
)

if st.button("Run analysis"):
    try:
        PromptInjectionGuard.sanitize(question)
        if not st.session_state.schema_loaded:
            st.warning("Please load the schema catalog first.")
            st.stop()

        catalog = st.session_state.catalog
        schema_summary = build_schema_summary(catalog)
        generated_sql = guess_sql_from_question(question, catalog)
        valid, risk, reason = validate_sql(generated_sql)
        if not valid:
            st.warning(f"Generated SQL was rejected: {reason}")
            st.stop()

        service = OracleDiscoveryService(oracle_cfg)
        service.connect()
        result = service.execute_select(generated_sql, max_rows=50)

        response_text = ask_llm(question, schema_summary, role="ANALYST")

        st.success("Investigation completed")
        st.markdown("### Generated SQL")
        st.code(generated_sql, language="sql")

        st.markdown("### Query risk")
        st.write(classify_query_risk(generated_sql))

        st.markdown("### Evidence")
        st.dataframe(pd.DataFrame(result["rows"]))

        st.markdown("### CIM Agent answer")
        st.markdown(response_text)

        audit_logger.write({
            "event": "question_processed",
            "question": question,
            "schema": catalog.get("schema"),
            "generated_sql": generated_sql,
            "row_count": result.get("row_count", 0),
        })

    except Exception as exc:
        st.error(f"Analysis failed: {exc}")
        audit_logger.write({"event": "question_failed", "question": question, "error": str(exc)})

st.markdown("---")
st.caption("CIM Agent is designed for enterprise investigation workflows: schema-aware, SQL-safe, evidence-based, and production-ready for Oracle metadata discovery.")


# Allow direct execution for debug if needed
if __name__ == "__main__":
    pass
