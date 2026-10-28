from __future__ import annotations

import re
import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from pymongo import ASCENDING, DESCENDING, MongoClient
from pymongo.errors import PyMongoError

from backend.app.core.config import (
    DET_ALERT_THRESHOLD,
    DET_ANOMALY_THRESHOLD,
    DET_DOS_THRESHOLD,
    DET_PORTSCAN_THRESHOLD,
    DET_RISK_THRESHOLD,
    MONGODB_ALERTS_COLLECTION,
    MONGODB_ANALYSIS_COLLECTION,
    MONGODB_DB,
    MONGODB_MODEL_COLLECTION,
    MONGODB_SETTINGS_COLLECTION,
    MONGODB_URI,
)
from backend.app.core.logging import logger

DEFAULT_SETTINGS: dict[str, float] = {
    'alert_threshold': DET_ALERT_THRESHOLD,
    'risk_threshold': DET_RISK_THRESHOLD,
    'portscan_threshold': DET_PORTSCAN_THRESHOLD,
    'dos_threshold': DET_DOS_THRESHOLD,
    'anomaly_threshold': DET_ANOMALY_THRESHOLD,
}


class FallbackStore:
    """Explicit process-memory store used when MongoDB is unavailable."""

    mode = 'memory-fallback'

    def __init__(self) -> None:
        self.alerts: list[dict[str, Any]] = []
        self.events: list[dict[str, Any]] = []
        self.analysis_history: list[dict[str, Any]] = []
        self.model_metadata: list[dict[str, Any]] = []
        self.settings = DEFAULT_SETTINGS.copy()

    def add_alert(self, alert: dict[str, Any]) -> dict[str, Any]:
        saved = dict(alert)
        saved['created_at'] = saved.get('created_at') or datetime.now(timezone.utc).isoformat()
        saved['_id'] = str(uuid.uuid4())
        self.alerts.append(saved)
        self.events.append({'event_type': 'alert', 'timestamp': saved['created_at'], 'payload': saved})
        return saved

    def record_analysis(self, analysis: dict[str, Any]) -> None:
        self.analysis_history.append({**analysis, 'timestamp': datetime.now(timezone.utc).isoformat()})

    def get_alerts(
        self,
        severity: str | None = None,
        category: str | None = None,
        search: str | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        items = list(self.alerts)
        if severity:
            items = [item for item in items if item.get('severity') == severity]
        if category:
            items = [item for item in items if item.get('category') == category]
        if search:
            needle = search.casefold()
            items = [
                item for item in items
                if any(needle in str(item.get(field, '')).casefold() for field in ('source_ip', 'destination_ip', 'category', 'prediction', 'alert_id'))
            ]
        items.sort(key=lambda item: item.get('created_at', ''), reverse=True)
        return items[offset:offset + limit], len(items)

    def get_alert(self, alert_id: str) -> dict[str, Any] | None:
        return next((item for item in self.alerts if item.get('alert_id') == alert_id), None)

    def get_latest_events(self, limit: int = 20) -> list[dict[str, Any]]:
        return sorted(self.events, key=lambda item: item.get('timestamp', ''), reverse=True)[:limit]

    def get_settings(self) -> dict[str, float]:
        return self.settings.copy()

    def set_settings(self, settings: dict[str, float]) -> dict[str, float]:
        self.settings.update(settings)
        return self.get_settings()

    def register_model_metadata(self, metadata: dict[str, Any]) -> dict[str, Any]:
        self.model_metadata.append(metadata)
        return metadata

    def get_dashboard_summary(self) -> dict[str, Any]:
        severity_counts = Counter(item.get('severity', 'LOW') for item in self.alerts)
        trend_counts: dict[str, Counter[str]] = {}
        for item in self.alerts:
            day = str(item.get('created_at', item.get('timestamp', '')))[:10]
            if not day:
                continue
            trend_counts.setdefault(day, Counter())
            trend_counts[day]['threats' if item.get('prediction') == 'malicious' else 'benign'] += 1
        trends = [
            {'label': day, 'threats': counts['threats'], 'benign': counts['benign']}
            for day, counts in sorted(trend_counts.items())[-14:]
        ]
        threats = sum(item.get('prediction') == 'malicious' for item in self.alerts)
        return {
            'total_records': len(self.alerts),
            'total_threats': threats,
            'high_and_critical': sum(item.get('severity') in {'HIGH', 'CRITICAL'} for item in self.alerts),
            'benign_count': len(self.alerts) - threats,
            'suspicious_count': threats,
            'severity_counts': dict(severity_counts),
            'alert_trends': trends,
        }


class MongoStore:
    mode = 'mongodb'

    def __init__(self, client: MongoClient) -> None:
        database = client[MONGODB_DB]
        self.alerts = database[MONGODB_ALERTS_COLLECTION]
        self.analysis_history = database[MONGODB_ANALYSIS_COLLECTION]
        self.models = database[MONGODB_MODEL_COLLECTION]
        self.settings = database[MONGODB_SETTINGS_COLLECTION]
        self.alerts.create_index([('alert_id', ASCENDING)], unique=True)
        self.alerts.create_index([('created_at', DESCENDING)])
        self.alerts.create_index([('severity', ASCENDING), ('category', ASCENDING)])
        self.analysis_history.create_index([('timestamp', DESCENDING)])

    @staticmethod
    def _clean(document: dict[str, Any] | None) -> dict[str, Any] | None:
        if document is not None:
            document['_id'] = str(document['_id'])
        return document

    def add_alert(self, alert: dict[str, Any]) -> dict[str, Any]:
        saved = dict(alert)
        saved['created_at'] = saved.get('created_at') or datetime.now(timezone.utc).isoformat()
        self.alerts.insert_one(saved)
        return saved

    def record_analysis(self, analysis: dict[str, Any]) -> None:
        self.analysis_history.insert_one({**analysis, 'timestamp': datetime.now(timezone.utc).isoformat()})

    def get_alerts(
        self,
        severity: str | None = None,
        category: str | None = None,
        search: str | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        query: dict[str, Any] = {}
        if severity:
            query['severity'] = severity
        if category:
            query['category'] = category
        if search:
            pattern = re.escape(search)
            query['$or'] = [
                {field: {'$regex': pattern, '$options': 'i'}}
                for field in ('source_ip', 'destination_ip', 'category', 'prediction', 'alert_id')
            ]
        total = self.alerts.count_documents(query)
        items = [self._clean(item) for item in self.alerts.find(query).sort('created_at', DESCENDING).skip(offset).limit(limit)]
        return [item for item in items if item is not None], total

    def get_alert(self, alert_id: str) -> dict[str, Any] | None:
        return self._clean(self.alerts.find_one({'alert_id': alert_id}))

    def get_latest_events(self, limit: int = 20) -> list[dict[str, Any]]:
        alerts = [self._clean(item) for item in self.alerts.find().sort('created_at', DESCENDING).limit(limit)]
        return [
            {'event_type': 'alert', 'timestamp': item.get('created_at'), 'payload': item}
            for item in alerts if item is not None
        ]

    def get_settings(self) -> dict[str, float]:
        doc = self.settings.find_one({'_id': 'detection'})
        return {**DEFAULT_SETTINGS, **(doc or {}).get('values', {})}

    def set_settings(self, settings: dict[str, float]) -> dict[str, float]:
        values = {**self.get_settings(), **settings}
        self.settings.update_one({'_id': 'detection'}, {'$set': {'values': values}}, upsert=True)
        return values

    def register_model_metadata(self, metadata: dict[str, Any]) -> dict[str, Any]:
        self.models.update_one({'model_name': metadata.get('model_name')}, {'$set': metadata}, upsert=True)
        return metadata

    def get_dashboard_summary(self) -> dict[str, Any]:
        grouped = list(self.alerts.aggregate([
            {'$group': {
                '_id': {'severity': '$severity', 'prediction': '$prediction'},
                'count': {'$sum': 1},
            }},
        ]))
        severity_counts: Counter[str] = Counter()
        threats = high_critical = 0
        for item in grouped:
            count = item['count']
            severity = item['_id'].get('severity', 'LOW')
            prediction = item['_id'].get('prediction')
            severity_counts[severity] += count
            threats += count if prediction == 'malicious' else 0
            high_critical += count if severity in {'HIGH', 'CRITICAL'} else 0
        trend_rows = list(self.alerts.aggregate([
            {'$group': {
                '_id': {'day': {'$substrCP': [{'$ifNull': ['$created_at', '$timestamp']}, 0, 10]}, 'prediction': '$prediction'},
                'count': {'$sum': 1},
            }},
            {'$sort': {'_id.day': 1}},
            {'$limit': 100},
        ]))
        days: dict[str, Counter[str]] = {}
        for item in trend_rows:
            day = item['_id'].get('day', '')
            if day:
                days.setdefault(day, Counter())
                days[day]['threats' if item['_id'].get('prediction') == 'malicious' else 'benign'] += item['count']
        return {
            'total_records': sum(severity_counts.values()),
            'total_threats': threats,
            'high_and_critical': high_critical,
            'benign_count': sum(severity_counts.values()) - threats,
            'suspicious_count': threats,
            'severity_counts': dict(severity_counts),
            'alert_trends': [
                {'label': day, 'threats': counts['threats'], 'benign': counts['benign']}
                for day, counts in sorted(days.items())[-14:]
            ],
        }


fallback_store = FallbackStore()
active_store: FallbackStore | MongoStore = fallback_store
database_status = 'memory-fallback'
_mongo_client: MongoClient | None = None


def configure_store() -> str:
    """Use MongoDB only after an actual ping; never claim persistence on failure."""
    global active_store, database_status, _mongo_client
    client = MongoClient(
        MONGODB_URI,
        serverSelectionTimeoutMS=1200,
        connectTimeoutMS=1200,
        appname='ThreatLensAI',
    )
    try:
        client.admin.command('ping')
        active_store = MongoStore(client)
        _mongo_client = client
        database_status = 'mongodb'
        logger.info('MongoDB persistence enabled.')
    except PyMongoError as exc:
        client.close()
        active_store = fallback_store
        _mongo_client = None
        database_status = 'memory-fallback'
        logger.warning('MongoDB unavailable; using process-memory fallback (%s).', type(exc).__name__)
    return database_status


def get_store() -> FallbackStore | MongoStore:
    return active_store


def get_database_status() -> str:
    return database_status


def activate_fallback(reason: str) -> None:
    global active_store, database_status, _mongo_client
    if _mongo_client is not None:
        _mongo_client.close()
    _mongo_client = None
    active_store = fallback_store
    database_status = 'memory-fallback'
    logger.error('Switched to process-memory fallback after a MongoDB operation failed (%s).', reason)
