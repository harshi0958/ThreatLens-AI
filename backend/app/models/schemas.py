from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class TrafficRecord(BaseModel):
    model_config = ConfigDict(extra='forbid', protected_namespaces=())

    timestamp: Optional[str] = None
    src_ip: str = Field(..., min_length=1, max_length=64, description='Source IP or host identifier')
    dst_ip: str = Field(..., min_length=1, max_length=64, description='Destination IP or host identifier')
    protocol: Literal['TCP', 'UDP'] = Field(..., description='Transport protocol')
    src_port: int = Field(..., ge=0, le=65535)
    dst_port: int = Field(..., ge=0, le=65535)
    duration: float = Field(..., ge=0, allow_inf_nan=False)
    bytes_sent: float = Field(..., ge=0, allow_inf_nan=False)
    bytes_received: float = Field(..., ge=0, allow_inf_nan=False)
    packet_count: float = Field(..., ge=0, allow_inf_nan=False)
    failed_login_count: int = Field(..., ge=0)
    login_attempts: int = Field(..., ge=0)
    connection_state: Literal['ESTABLISHED', 'SYN_SCAN', 'SYN_SENT', 'TIME_WAIT', 'FIN_WAIT', 'REJECTED']
    traffic_volume: float = Field(..., ge=0, allow_inf_nan=False)
    anomaly_score: float = Field(..., ge=0, le=1, allow_inf_nan=False)
    is_simulated: bool = Field(default=True)


class ModelStatus(BaseModel):
    model_config = ConfigDict(extra='ignore', protected_namespaces=())

    model_name: str
    status: str
    feature_schema: List[str]
    model_path: str
    has_training_data: bool
    created_at: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AlertRecord(BaseModel):
    alert_id: str
    timestamp: str
    severity: Literal['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    category: str
    source_ip: str
    destination_ip: str
    risk_score: float
    confidence: float
    prediction: str
    reasons: List[str]
    metadata: Dict[str, Any] = Field(default_factory=dict)


class DatasetValidationResult(BaseModel):
    valid: bool
    row_count: int
    columns: List[str]
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)


class AnalysisSummary(BaseModel):
    total_records: int
    total_threats: int
    high_and_critical: int
    benign_count: int
    suspicious_count: int
    severity_counts: Dict[str, int]
    alert_trends: List[Dict[str, Any]]


class SettingsUpdate(BaseModel):
    model_config = ConfigDict(extra='forbid')

    alert_threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    risk_threshold: float = Field(default=65.0, ge=0.0, le=100.0)
    portscan_threshold: float = Field(default=0.6, ge=0.0, le=1.0)
    dos_threshold: float = Field(default=0.7, ge=0.0, le=1.0)
    anomaly_threshold: float = Field(default=0.58, ge=0.0, le=1.0)
