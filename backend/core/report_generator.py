"""
Report Generator Module

Generates PDF, CSV, and JSON reports for backup system data.
Uses ReportLab for PDF generation.
"""

import csv
import io
import json
import logging
import os
from html import escape
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from sqlalchemy.orm import Session

from models import Agent, Backup, Report, Schedule, VM
from .product_identity import product_name

logger = logging.getLogger(__name__)

# Report storage directory (configurable via env var)
REPORT_STORAGE_PATH = os.environ.get("REPORT_STORAGE_PATH", "/tmp/reports")


def parse_date_range(filters: Dict) -> Tuple[Optional[datetime], Optional[datetime]]:
    """Parse date range from report filters."""
    date_range = filters.get("date_range", "30d")
    now = datetime.utcnow()

    if date_range == "7d":
        start = now - timedelta(days=7)
    elif date_range == "30d":
        start = now - timedelta(days=30)
    elif date_range == "90d":
        start = now - timedelta(days=90)
    elif date_range == "custom":
        start_str = filters.get("start_date")
        end_str = filters.get("end_date")
        start = (
            datetime.fromisoformat(start_str) if start_str else now - timedelta(days=30)
        )
        end = datetime.fromisoformat(end_str) if end_str else now
        return start, end
    else:
        start = now - timedelta(days=30)

    return start, now


def format_bytes(size_bytes: Optional[int]) -> str:
    """Format bytes to human-readable string."""
    if size_bytes is None:
        return "N/A"
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(size_bytes) < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} PB"


def format_duration(seconds: Optional[float]) -> str:
    """Format seconds to human-readable duration string."""
    if seconds is None:
        return "N/A"
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    minutes, secs = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {secs}s" if secs else f"{minutes}m"
    hours, mins = divmod(minutes, 60)
    if hours < 24:
        return f"{hours}h {mins}m" if mins else f"{hours}h"
    days, hrs = divmod(hours, 24)
    return f"{days}d {hrs}h" if hrs else f"{days}d"


def format_percent(value: Optional[float]) -> str:
    """Format a float as a percentage string."""
    if value is None:
        return "N/A"
    return f"{value:.1f}%"


def format_datetime(dt: Optional[datetime]) -> str:
    """Format datetime for display."""
    if dt is None:
        return "N/A"
    return dt.strftime("%Y-%m-%d %H:%M:%S")


# Human-readable labels for common data keys
FIELD_LABELS: Dict[str, str] = {
    # Counts / totals
    "total": "Total",
    "total_backups": "Total Backups",
    "total_failed": "Total Failed",
    "total_vms": "Total VMs",
    "backup_count": "Backup Count",
    "vm_count": "VM Count",
    "disk_count": "Disk Count",
    # Statuses
    "completed_backups": "Completed",
    "failed_backups": "Failed",
    "completed": "Completed",
    "failed": "Failed",
    "pending": "Pending",
    "running": "Running",
    "enabled": "Enabled",
    "disabled": "Disabled",
    "online": "Online",
    "offline": "Offline",
    # Sizes / performance
    "total_size": "Total Size",
    "total_size_bytes": "Total Size",
    "size": "Size",
    "size_bytes": "Size",
    "avg_duration_seconds": "Average Duration",
    # Rates / percentages
    "success_rate": "Success Rate",
    # Nested sections
    "top_vms": "Top VMs by Backup Count",
    "backup_types": "Backup Types",
    "by_type": "By Type",
    "by_status": "By Status",
    "by_state": "By State",
    "by_vm": "By VM",
    "by_agent": "By Agent",
    # Schedule fields
    "cron": "Schedule",
    "backup_type": "Backup Type",
    "target_type": "Target Type",
    "retention_days": "Retention (days)",
    "last_run": "Last Run",
    "next_run": "Next Run",
    # Agent fields
    "hostname": "Hostname",
    "ip_address": "IP Address",
    "last_heartbeat": "Last Heartbeat",
    "recent_completed": "Recent Completed",
    "recent_failed": "Recent Failed",
    "total_memory_gb": "Total Memory",
    "total_vcpus": "Total vCPUs",
    "memory_gb": "Memory",
    "vcpus": "vCPUs",
    "last_backup": "Last Backup",
}


def _label(key: str) -> str:
    """Return a human-readable label for a data key."""
    return FIELD_LABELS.get(key, key.replace("_", " ").title())


class BaseReportGenerator(ABC):
    """Base class for all report generators."""

    def __init__(self, report: Report, db: Session):
        self.report = report
        self.db = db
        self.filters = report.filters or {}
        self.start_date, self.end_date = parse_date_range(self.filters)
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self):
        """Set up custom paragraph styles."""
        self.styles.add(
            ParagraphStyle(
                name="ReportTitle",
                parent=self.styles["Heading1"],
                fontSize=18,
                spaceAfter=12,
                textColor=colors.HexColor("#1a365d"),
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="ReportSubtitle",
                parent=self.styles["Normal"],
                fontSize=10,
                textColor=colors.gray,
                spaceAfter=20,
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="SectionHeader",
                parent=self.styles["Heading2"],
                fontSize=14,
                spaceBefore=16,
                spaceAfter=8,
                textColor=colors.HexColor("#2c5282"),
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="SummaryText",
                parent=self.styles["Normal"],
                fontSize=11,
                spaceAfter=6,
            )
        )

    @abstractmethod
    def get_title(self) -> str:
        """Return report title."""
        pass

    @abstractmethod
    def get_data(self) -> Dict[str, Any]:
        """Fetch and return report data."""
        pass

    @abstractmethod
    def build_pdf_content(self, data: Dict[str, Any]) -> List:
        """Build PDF content elements from data."""
        pass

    @abstractmethod
    def build_csv_content(self, data: Dict[str, Any]) -> List[List[str]]:
        """Build CSV rows from data."""
        pass

    def generate(self) -> Tuple[bytes, str]:
        """Generate report in specified format."""
        data = self.get_data()

        if self.report.format == "pdf":
            return self._generate_pdf(data)
        elif self.report.format == "csv":
            return self._generate_csv(data)
        elif self.report.format == "html":
            return self._generate_html(data)
        else:
            return self._generate_json(data)

    def _generate_pdf(self, data: Dict[str, Any]) -> Tuple[bytes, str]:
        """Generate PDF report."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=20 * mm,
            leftMargin=20 * mm,
            topMargin=20 * mm,
            bottomMargin=20 * mm,
        )

        # Build content
        elements = []

        # Header
        elements.append(Paragraph(self.get_title(), self.styles["ReportTitle"]))
        elements.append(
            Paragraph(
                f"Generated: {format_datetime(datetime.utcnow())} | "
                f"Period: {format_datetime(self.start_date)} to {format_datetime(self.end_date)}",
                self.styles["ReportSubtitle"],
            )
        )
        elements.append(Spacer(1, 10))

        # Report-specific content
        elements.extend(self.build_pdf_content(data))

        # Footer
        elements.append(Spacer(1, 20))
        elements.append(
            Paragraph(
                escape(product_name()) + " Backup System", self.styles["ReportSubtitle"]
            )
        )

        # Build PDF
        doc.build(elements)

        content = buffer.getvalue()
        filename = f"{self.report.name.replace(' ', '_')}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
        return content, filename

    def _generate_csv(self, data: Dict[str, Any]) -> Tuple[bytes, str]:
        """Generate CSV report."""
        buffer = io.StringIO()
        writer = csv.writer(buffer)

        rows = self.build_csv_content(data)
        for row in rows:
            writer.writerow(row)

        content = buffer.getvalue().encode("utf-8")
        filename = f"{self.report.name.replace(' ', '_')}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
        return content, filename

    def _generate_json(self, data: Dict[str, Any]) -> Tuple[bytes, str]:
        """Generate JSON report."""
        output = {
            "report": self.report.name,
            "type": self.report.report_type,
            "generated": datetime.utcnow().isoformat() + "Z",
            "period": {
                "start": self.start_date.isoformat() + "Z" if self.start_date else None,
                "end": self.end_date.isoformat() + "Z" if self.end_date else None,
            },
            "data": data,
        }

        content = json.dumps(output, indent=2, default=str).encode("utf-8")
        filename = f"{self.report.name.replace(' ', '_')}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        return content, filename

    def _generate_html(self, data: Dict[str, Any]) -> Tuple[bytes, str]:
        """Generate HTML report."""
        rows_html = self.build_html_content(data)
        now = format_datetime(datetime.utcnow())
        period = (
            f"{format_datetime(self.start_date)} to {format_datetime(self.end_date)}"
        )
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{self.get_title()}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 40px; color: #222; }}
    h1 {{ color: #1a365d; border-bottom: 2px solid #2c5282; padding-bottom: 8px; }}
    h2 {{ color: #2c5282; margin-top: 32px; }}
    .meta {{ color: #666; font-size: 0.9em; margin-bottom: 24px; }}
    table {{ border-collapse: collapse; width: 100%; margin: 16px 0; }}
    th {{ background: #2c5282; color: #fff; padding: 8px 12px; text-align: left; font-size: 0.9em; }}
    td {{ padding: 7px 12px; font-size: 0.88em; border-bottom: 1px solid #e2e8f0; }}
    tr:nth-child(even) td {{ background: #f7fafc; }}
    .summary {{ background: #ebf4ff; border-left: 4px solid #2c5282; padding: 12px 16px; margin: 16px 0; }}
    footer {{ margin-top: 48px; color: #999; font-size: 0.8em; border-top: 1px solid #e2e8f0; padding-top: 8px; }}
  </style>
</head>
<body>
  <h1>{self.get_title()}</h1>
  <div class="meta">Generated: {now} | Period: {period}</div>
  {rows_html}
  <footer>{escape(product_name())} Backup System</footer>
</body>
</html>"""
        content = html.encode("utf-8")
        filename = f"{self.report.name.replace(' ', '_')}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.html"
        return content, filename

    # --- HTML helpers ---------------------------------------------------------

    @staticmethod
    def _html_subtable_from_dict(d: Dict, key_fmt=None) -> str:
        """Render a flat dict as a two-column HTML table (key / value)."""
        if key_fmt is None:
            key_fmt = _label
        rows = "".join(
            f"<tr><td><strong>{key_fmt(k)}</strong></td>"
            f"<td>{BaseReportGenerator._fmt_html_value(k, v)}</td></tr>"
            for k, v in d.items()
        )
        return f"<table><tbody>{rows}</tbody></table>"

    @staticmethod
    def _html_subtable_from_list_of_dicts(rows_data: List[Dict]) -> str:
        """Render a list of dicts as an HTML table with labelled column headers."""
        if not rows_data:
            return "<em>none</em>"
        headers = list(rows_data[0].keys())
        header_html = "".join(f"<th>{_label(h)}</th>" for h in headers)
        body_html = "".join(
            "<tr>"
            + "".join(
                f"<td>{BaseReportGenerator._fmt_html_value(h, row.get(h, ''))}</td>"
                for h in headers
            )
            + "</tr>"
            for row in rows_data
        )
        return (
            f"<table><thead><tr>{header_html}</tr></thead>"
            f"<tbody>{body_html}</tbody></table>"
        )

    @staticmethod
    def _html_subtable_from_list_of_tuples(
        rows_data: List[Tuple], col_headers: List[str]
    ) -> str:
        """Render a list of (name, stats_dict) tuples as an HTML table."""
        if not rows_data:
            return "<em>none</em>"
        # Detect if second element is a dict and expand its keys as columns
        first = rows_data[0]
        if isinstance(first[1], dict):
            stat_keys = list(first[1].keys())
            all_headers = col_headers[:1] + stat_keys
            header_html = "".join(f"<th>{_label(h)}</th>" for h in all_headers)
            body_html = "".join(
                "<tr>"
                + f"<td>{row[0]}</td>"
                + "".join(
                    f"<td>{BaseReportGenerator._fmt_html_value(k, row[1].get(k, ''))}</td>"
                    for k in stat_keys
                )
                + "</tr>"
                for row in rows_data
            )
        else:
            header_html = "".join(f"<th>{_label(h)}</th>" for h in col_headers)
            body_html = "".join(
                "<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>"
                for row in rows_data
            )
        return (
            f"<table><thead><tr>{header_html}</tr></thead>"
            f"<tbody>{body_html}</tbody></table>"
        )

    @staticmethod
    def _fmt_html_value(key: str, value: Any) -> str:
        """Format a single value for HTML display, applying type-aware formatting."""
        if value is None:
            return ""
        # Byte fields
        if key in ("size", "size_bytes", "total_size", "total_size_bytes"):
            return (
                format_bytes(value) if isinstance(value, (int, float)) else str(value)
            )
        # Duration fields
        if key in ("avg_duration_seconds", "duration_seconds"):
            return (
                format_duration(value)
                if isinstance(value, (int, float))
                else str(value)
            )
        # Percentage fields
        if key in ("success_rate",):
            return (
                format_percent(value) if isinstance(value, (int, float)) else str(value)
            )
        # Memory in GB
        if key in ("memory_gb", "total_memory_gb"):
            return f"{value:.1f} GB" if isinstance(value, (int, float)) else str(value)
        # Datetime objects
        if isinstance(value, datetime):
            return format_datetime(value)
        # Nested dict → sub-table
        if isinstance(value, dict):
            return BaseReportGenerator._html_subtable_from_dict(value)
        # List of dicts → sub-table
        if isinstance(value, list):
            if not value:
                return "<em>none</em>"
            if isinstance(value[0], dict):
                return BaseReportGenerator._html_subtable_from_list_of_dicts(value)
            if isinstance(value[0], tuple):
                return BaseReportGenerator._html_subtable_from_list_of_tuples(
                    value, ["Name", "Value"]
                )
            return ", ".join(str(i) for i in value)
        return str(value)

    # --- Default HTML builder ------------------------------------------------

    def build_html_content(self, data: Dict[str, Any]) -> str:
        """Build HTML body content from data. Override in subclasses for rich output.
        Default: render the data dict as an HTML table of labelled key/value pairs,
        with type-aware formatting and nested sub-tables instead of raw JSON."""

        rows_html = "".join(
            f"<tr><td><strong>{_label(k)}</strong></td>"
            f"<td>{self._fmt_html_value(k, v)}</td></tr>"
            for k, v in data.items()
        )
        return f"<h2>Report Data</h2><table><tbody>{rows_html}</tbody></table>"

    def _create_table(
        self, data: List[List[str]], col_widths: Optional[List[float]] = None
    ) -> Table:
        """Create a styled table."""
        table = Table(data, colWidths=col_widths)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c5282")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 10),
                    ("ALIGN", (0, 0), (-1, 0), "CENTER"),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
                    ("TOPPADDING", (0, 0), (-1, 0), 8),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.white),
                    ("TEXTCOLOR", (0, 1), (-1, -1), colors.black),
                    ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                    ("FONTSIZE", (0, 1), (-1, -1), 9),
                    ("ALIGN", (0, 1), (-1, -1), "LEFT"),
                    ("BOTTOMPADDING", (0, 1), (-1, -1), 6),
                    ("TOPPADDING", (0, 1), (-1, -1), 6),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [colors.white, colors.HexColor("#f7fafc")],
                    ),
                ]
            )
        )
        return table


class FailedBackupsReport(BaseReportGenerator):
    """Report on failed backup jobs."""

    def get_title(self) -> str:
        return "Failed Backups Report"

    def get_data(self) -> Dict[str, Any]:
        """Get failed backup data."""
        query = (
            self.db.query(Backup)
            .filter(
                Backup.status == "failed",
                Backup.created_at >= self.start_date,
                Backup.created_at <= self.end_date,
            )
            .order_by(Backup.created_at.desc())
        )

        failed_backups = query.all()

        # Aggregate by VM
        by_vm = {}
        for backup in failed_backups:
            vm = self.db.query(VM).filter(VM.id == backup.vm_id).first()
            vm_name = vm.name if vm else backup.vm_id
            if vm_name not in by_vm:
                by_vm[vm_name] = 0
            by_vm[vm_name] += 1

        # Build details list
        details = []
        for backup in failed_backups:
            vm = self.db.query(VM).filter(VM.id == backup.vm_id).first()
            agent = None
            if vm:
                agent = self.db.query(Agent).filter(Agent.id == vm.agent_id).first()

            error_msg = (
                backup.tags.get("error", "Unknown error")
                if backup.tags
                else "Unknown error"
            )

            details.append(
                {
                    "backup_id": backup.id[:8],
                    "vm_name": vm.name if vm else "Unknown",
                    "agent": agent.get_display_name() if agent else "Unknown",
                    "type": backup.backup_type or "full",
                    "created_at": backup.created_at,
                    "error": error_msg[:100],  # Truncate long errors
                }
            )

        return {
            "total_failed": len(failed_backups),
            "by_vm": by_vm,
            "details": details,
        }

    def build_pdf_content(self, data: Dict[str, Any]) -> List:
        """Build PDF content for failed backups report."""
        elements = []

        # Summary
        elements.append(Paragraph("Summary", self.styles["SectionHeader"]))
        elements.append(
            Paragraph(
                f"Total failed backups: <b>{data['total_failed']}</b>",
                self.styles["SummaryText"],
            )
        )
        elements.append(Spacer(1, 10))

        # Failures by VM
        if data["by_vm"]:
            elements.append(Paragraph("Failures by VM", self.styles["SectionHeader"]))
            table_data = [["VM Name", "Failed Count"]]
            for vm_name, count in sorted(data["by_vm"].items(), key=lambda x: -x[1]):
                table_data.append([vm_name, str(count)])
            elements.append(self._create_table(table_data, [300, 100]))
            elements.append(Spacer(1, 15))

        # Details table
        if data["details"]:
            elements.append(
                Paragraph("Failed Backup Details", self.styles["SectionHeader"])
            )
            table_data = [["ID", "VM", "Agent", "Type", "Date", "Error"]]
            for d in data["details"][:50]:  # Limit to 50 rows
                table_data.append(
                    [
                        d["backup_id"],
                        d["vm_name"][:20],
                        d["agent"][:15],
                        d["type"],
                        format_datetime(d["created_at"])[:16],
                        d["error"][:30] + "..." if len(d["error"]) > 30 else d["error"],
                    ]
                )
            elements.append(self._create_table(table_data, [50, 80, 70, 40, 90, 150]))

        return elements

    def build_csv_content(self, data: Dict[str, Any]) -> List[List[str]]:
        """Build CSV content for failed backups report."""
        rows = [
            ["Failed Backups Report"],
            [f"Generated: {format_datetime(datetime.utcnow())}"],
            [
                f"Period: {format_datetime(self.start_date)} to {format_datetime(self.end_date)}"
            ],
            [],
            ["Summary"],
            ["Total Failed", str(data["total_failed"])],
            [],
            ["Backup ID", "VM Name", "Agent", "Type", "Created At", "Error"],
        ]

        for d in data["details"]:
            rows.append(
                [
                    d["backup_id"],
                    d["vm_name"],
                    d["agent"],
                    d["type"],
                    format_datetime(d["created_at"]),
                    d["error"],
                ]
            )

        return rows

    def build_html_content(self, data: Dict[str, Any]) -> str:
        """Build HTML content for failed backups report."""
        parts = []

        # Summary box
        parts.append(
            f'<div class="summary">'
            f"<strong>Total Failed:</strong> {data['total_failed']}"
            f"</div>"
        )

        # Failures by VM
        if data["by_vm"]:
            parts.append("<h2>Failures by VM</h2>")
            rows_html = "".join(
                f"<tr><td>{vm_name}</td><td>{count}</td></tr>"
                for vm_name, count in sorted(data["by_vm"].items(), key=lambda x: -x[1])
            )
            parts.append(
                f"<table><thead><tr><th>VM Name</th><th>Failed Count</th></tr></thead>"
                f"<tbody>{rows_html}</tbody></table>"
            )

        # Details table
        if data["details"]:
            parts.append("<h2>Failed Backup Details</h2>")
            header = (
                "<thead><tr>"
                "<th>Backup ID</th><th>VM</th><th>Agent</th>"
                "<th>Type</th><th>Date</th><th>Error</th>"
                "</tr></thead>"
            )
            body_rows = "".join(
                f"<tr>"
                f"<td>{d['backup_id']}</td>"
                f"<td>{d['vm_name']}</td>"
                f"<td>{d['agent']}</td>"
                f"<td>{d['type'].capitalize()}</td>"
                f"<td>{format_datetime(d['created_at'])}</td>"
                f"<td>{d['error']}</td>"
                f"</tr>"
                for d in data["details"][:50]
            )
            parts.append(f"<table>{header}<tbody>{body_rows}</tbody></table>")

        return "\n".join(parts)


class BackupSummaryReport(BaseReportGenerator):
    """Comprehensive backup summary report."""

    def get_title(self) -> str:
        return "Backup Summary Report"

    def get_data(self) -> Dict[str, Any]:
        """Get backup summary data."""
        # Total backups by status
        backups = (
            self.db.query(Backup)
            .filter(
                Backup.created_at >= self.start_date,
                Backup.created_at <= self.end_date,
            )
            .all()
        )

        by_status = {"completed": 0, "failed": 0, "pending": 0, "running": 0}
        by_type = {"full": 0, "incremental": 0, "differential": 0}
        total_size = 0

        for backup in backups:
            status = backup.status or "pending"
            by_status[status] = by_status.get(status, 0) + 1

            btype = backup.backup_type or "full"
            by_type[btype] = by_type.get(btype, 0) + 1

            if backup.size_bytes:
                total_size += backup.size_bytes

        # By VM (top 10)
        vm_counts = {}
        for backup in backups:
            vm = self.db.query(VM).filter(VM.id == backup.vm_id).first()
            vm_name = vm.name if vm else backup.vm_id
            if vm_name not in vm_counts:
                vm_counts[vm_name] = {
                    "total": 0,
                    "completed": 0,
                    "failed": 0,
                    "size": 0,
                }
            vm_counts[vm_name]["total"] += 1
            if backup.status == "completed":
                vm_counts[vm_name]["completed"] += 1
            elif backup.status == "failed":
                vm_counts[vm_name]["failed"] += 1
            if backup.size_bytes:
                vm_counts[vm_name]["size"] += backup.size_bytes

        top_vms = sorted(vm_counts.items(), key=lambda x: -x[1]["total"])[:10]

        # Success rate
        total = len(backups)
        success_rate = (by_status["completed"] / total * 100) if total > 0 else 0

        return {
            "total": total,
            "by_status": by_status,
            "by_type": by_type,
            "total_size": total_size,
            "success_rate": success_rate,
            "top_vms": top_vms,
        }

    def build_pdf_content(self, data: Dict[str, Any]) -> List:
        """Build PDF content for backup summary."""
        elements = []

        # Overview
        elements.append(Paragraph("Overview", self.styles["SectionHeader"]))
        elements.append(
            Paragraph(
                f"Total backups: <b>{data['total']}</b> | "
                f"Success rate: <b>{data['success_rate']:.1f}%</b> | "
                f"Total size: <b>{format_bytes(data['total_size'])}</b>",
                self.styles["SummaryText"],
            )
        )
        elements.append(Spacer(1, 10))

        # Status breakdown
        elements.append(Paragraph("Backup Status", self.styles["SectionHeader"]))
        table_data = [["Status", "Count", "Percentage"]]
        total = data["total"] or 1
        for status, count in data["by_status"].items():
            pct = count / total * 100
            table_data.append([status.capitalize(), str(count), f"{pct:.1f}%"])
        elements.append(self._create_table(table_data, [150, 100, 100]))
        elements.append(Spacer(1, 15))

        # Type breakdown
        elements.append(Paragraph("Backup Types", self.styles["SectionHeader"]))
        table_data = [["Type", "Count"]]
        for btype, count in data["by_type"].items():
            if count > 0:
                table_data.append([btype.capitalize(), str(count)])
        elements.append(self._create_table(table_data, [200, 100]))
        elements.append(Spacer(1, 15))

        # Top VMs
        if data["top_vms"]:
            elements.append(
                Paragraph("Top VMs by Backup Count", self.styles["SectionHeader"])
            )
            table_data = [["VM Name", "Total", "Completed", "Failed", "Size"]]
            for vm_name, stats in data["top_vms"]:
                table_data.append(
                    [
                        vm_name[:25],
                        str(stats["total"]),
                        str(stats["completed"]),
                        str(stats["failed"]),
                        format_bytes(stats["size"]),
                    ]
                )
            elements.append(self._create_table(table_data, [150, 60, 70, 60, 80]))

        return elements

    def build_csv_content(self, data: Dict[str, Any]) -> List[List[str]]:
        """Build CSV content for backup summary."""
        rows = [
            ["Backup Summary Report"],
            [f"Generated: {format_datetime(datetime.utcnow())}"],
            [
                f"Period: {format_datetime(self.start_date)} to {format_datetime(self.end_date)}"
            ],
            [],
            ["Overview"],
            ["Total Backups", str(data["total"])],
            ["Success Rate", f"{data['success_rate']:.1f}%"],
            ["Total Size", format_bytes(data["total_size"])],
            [],
            ["Status Breakdown"],
            ["Status", "Count"],
        ]
        for status, count in data["by_status"].items():
            rows.append([status.capitalize(), str(count)])

        rows.extend(
            [
                [],
                ["VM Name", "Total", "Completed", "Failed", "Size"],
            ]
        )
        for vm_name, stats in data["top_vms"]:
            rows.append(
                [
                    vm_name,
                    str(stats["total"]),
                    str(stats["completed"]),
                    str(stats["failed"]),
                    format_bytes(stats["size"]),
                ]
            )

        return rows

    def build_html_content(self, data: Dict[str, Any]) -> str:
        """Build HTML content for backup summary report."""
        total = data["total"] or 1
        parts = []

        # Summary box
        parts.append(
            f'<div class="summary">'
            f"<strong>Total Backups:</strong> {data['total']} &nbsp;|&nbsp; "
            f"<strong>Success Rate:</strong> {format_percent(data['success_rate'])} &nbsp;|&nbsp; "
            f"<strong>Total Size:</strong> {format_bytes(data['total_size'])}"
            f"</div>"
        )

        # Status breakdown
        parts.append("<h2>Backup Status</h2>")
        status_rows = "".join(
            f"<tr><td>{status.capitalize()}</td>"
            f"<td>{count}</td>"
            f"<td>{format_percent(count / total * 100)}</td></tr>"
            for status, count in data["by_status"].items()
        )
        parts.append(
            f"<table><thead><tr><th>Status</th><th>Count</th><th>Percentage</th></tr></thead>"
            f"<tbody>{status_rows}</tbody></table>"
        )

        # Backup types
        active_types = [(t, c) for t, c in data["by_type"].items() if c > 0]
        if active_types:
            parts.append("<h2>Backup Types</h2>")
            type_rows = "".join(
                f"<tr><td>{btype.capitalize()}</td><td>{count}</td></tr>"
                for btype, count in active_types
            )
            parts.append(
                f"<table><thead><tr><th>Type</th><th>Count</th></tr></thead>"
                f"<tbody>{type_rows}</tbody></table>"
            )

        # Top VMs
        if data["top_vms"]:
            parts.append("<h2>Top VMs by Backup Count</h2>")
            vm_rows = "".join(
                f"<tr>"
                f"<td>{vm_name}</td>"
                f"<td>{stats['total']}</td>"
                f"<td>{stats['completed']}</td>"
                f"<td>{stats['failed']}</td>"
                f"<td>{format_bytes(stats['size'])}</td>"
                f"</tr>"
                for vm_name, stats in data["top_vms"]
            )
            parts.append(
                f"<table><thead><tr>"
                f"<th>VM Name</th><th>Total</th><th>Completed</th><th>Failed</th><th>Size</th>"
                f"</tr></thead><tbody>{vm_rows}</tbody></table>"
            )

        return "\n".join(parts)


class VMInventoryReport(BaseReportGenerator):
    """Report listing all VMs and their details."""

    def get_title(self) -> str:
        return "VM Inventory Report"

    def get_data(self) -> Dict[str, Any]:
        """Get VM inventory data."""
        vms = self.db.query(VM).all()
        agents = {a.id: a for a in self.db.query(Agent).all()}

        vm_list = []
        by_state = {"running": 0, "stopped": 0, "unknown": 0}
        by_agent = {}
        total_memory = 0
        total_vcpus = 0

        for vm in vms:
            agent = agents.get(vm.agent_id)
            agent_name = agent.get_display_name() if agent else "Unknown"

            state = vm.state or "unknown"
            by_state[state] = by_state.get(state, 0) + 1

            by_agent[agent_name] = by_agent.get(agent_name, 0) + 1

            if vm.memory_kb:
                total_memory += vm.memory_kb
            if vm.vcpu_count:
                total_vcpus += vm.vcpu_count

            # Get last backup info
            last_backup = (
                self.db.query(Backup)
                .filter(Backup.vm_id == vm.id, Backup.status == "completed")
                .order_by(Backup.created_at.desc())
                .first()
            )

            vm_list.append(
                {
                    "name": vm.name,
                    "state": state,
                    "agent": agent_name,
                    "memory_gb": (vm.memory_kb / 1024 / 1024) if vm.memory_kb else 0,
                    "vcpus": vm.vcpu_count or 0,
                    "disk_count": len(vm.disks) if vm.disks else 0,
                    "last_backup": last_backup.created_at if last_backup else None,
                }
            )

        return {
            "total_vms": len(vms),
            "by_state": by_state,
            "by_agent": by_agent,
            "total_memory_gb": total_memory / 1024 / 1024 if total_memory else 0,
            "total_vcpus": total_vcpus,
            "vms": sorted(vm_list, key=lambda x: x["name"]),
        }

    def build_pdf_content(self, data: Dict[str, Any]) -> List:
        """Build PDF content for VM inventory."""
        elements = []

        # Summary
        elements.append(Paragraph("Summary", self.styles["SectionHeader"]))
        elements.append(
            Paragraph(
                f"Total VMs: <b>{data['total_vms']}</b> | "
                f"Total Memory: <b>{data['total_memory_gb']:.1f} GB</b> | "
                f"Total vCPUs: <b>{data['total_vcpus']}</b>",
                self.styles["SummaryText"],
            )
        )
        elements.append(Spacer(1, 10))

        # By state
        elements.append(Paragraph("VMs by State", self.styles["SectionHeader"]))
        table_data = [["State", "Count"]]
        for state, count in data["by_state"].items():
            if count > 0:
                table_data.append([state.capitalize(), str(count)])
        elements.append(self._create_table(table_data, [200, 100]))
        elements.append(Spacer(1, 15))

        # By agent
        elements.append(Paragraph("VMs by Agent", self.styles["SectionHeader"]))
        table_data = [["Agent", "VM Count"]]
        for agent_name, count in sorted(data["by_agent"].items(), key=lambda x: -x[1]):
            table_data.append([agent_name[:30], str(count)])
        elements.append(self._create_table(table_data, [250, 100]))
        elements.append(Spacer(1, 15))

        # VM list
        elements.append(Paragraph("VM Details", self.styles["SectionHeader"]))
        table_data = [["VM Name", "State", "Agent", "Memory", "vCPUs", "Last Backup"]]
        for vm in data["vms"][:50]:
            table_data.append(
                [
                    vm["name"][:25],
                    vm["state"],
                    vm["agent"][:15],
                    f"{vm['memory_gb']:.1f} GB",
                    str(vm["vcpus"]),
                    (
                        format_datetime(vm["last_backup"])[:10]
                        if vm["last_backup"]
                        else "Never"
                    ),
                ]
            )
        elements.append(self._create_table(table_data, [100, 50, 70, 55, 40, 80]))

        return elements

    def build_csv_content(self, data: Dict[str, Any]) -> List[List[str]]:
        """Build CSV content for VM inventory."""
        rows = [
            ["VM Inventory Report"],
            [f"Generated: {format_datetime(datetime.utcnow())}"],
            [],
            ["Summary"],
            ["Total VMs", str(data["total_vms"])],
            ["Total Memory (GB)", f"{data['total_memory_gb']:.1f}"],
            ["Total vCPUs", str(data["total_vcpus"])],
            [],
            [
                "VM Name",
                "State",
                "Agent",
                "Memory (GB)",
                "vCPUs",
                "Disks",
                "Last Backup",
            ],
        ]
        for vm in data["vms"]:
            rows.append(
                [
                    vm["name"],
                    vm["state"],
                    vm["agent"],
                    f"{vm['memory_gb']:.1f}",
                    str(vm["vcpus"]),
                    str(vm["disk_count"]),
                    (
                        format_datetime(vm["last_backup"])
                        if vm["last_backup"]
                        else "Never"
                    ),
                ]
            )
        return rows

    def build_html_content(self, data: Dict[str, Any]) -> str:
        """Build HTML content for VM inventory report."""
        parts = []

        # Summary box
        parts.append(
            f'<div class="summary">'
            f"<strong>Total VMs:</strong> {data['total_vms']} &nbsp;|&nbsp; "
            f"<strong>Total Memory:</strong> {data['total_memory_gb']:.1f} GB &nbsp;|&nbsp; "
            f"<strong>Total vCPUs:</strong> {data['total_vcpus']}"
            f"</div>"
        )

        # By state
        if any(c > 0 for c in data["by_state"].values()):
            parts.append("<h2>VMs by State</h2>")
            state_rows = "".join(
                f"<tr><td>{state.capitalize()}</td><td>{count}</td></tr>"
                for state, count in data["by_state"].items()
                if count > 0
            )
            parts.append(
                f"<table><thead><tr><th>State</th><th>Count</th></tr></thead>"
                f"<tbody>{state_rows}</tbody></table>"
            )

        # By agent
        if data["by_agent"]:
            parts.append("<h2>VMs by Agent</h2>")
            agent_rows = "".join(
                f"<tr><td>{agent_name}</td><td>{count}</td></tr>"
                for agent_name, count in sorted(
                    data["by_agent"].items(), key=lambda x: -x[1]
                )
            )
            parts.append(
                f"<table><thead><tr><th>Agent</th><th>VM Count</th></tr></thead>"
                f"<tbody>{agent_rows}</tbody></table>"
            )

        # VM details
        if data["vms"]:
            parts.append("<h2>VM Details</h2>")
            vm_rows = "".join(
                f"<tr>"
                f"<td>{vm['name']}</td>"
                f"<td>{vm['state'].capitalize()}</td>"
                f"<td>{vm['agent']}</td>"
                f"<td>{vm['memory_gb']:.1f} GB</td>"
                f"<td>{vm['vcpus']}</td>"
                f"<td>{vm['disk_count']}</td>"
                f"<td>{format_datetime(vm['last_backup']) if vm['last_backup'] else 'Never'}</td>"
                f"</tr>"
                for vm in data["vms"][:50]
            )
            parts.append(
                f"<table><thead><tr>"
                f"<th>VM Name</th><th>State</th><th>Agent</th>"
                f"<th>Memory</th><th>vCPUs</th><th>Disks</th><th>Last Backup</th>"
                f"</tr></thead><tbody>{vm_rows}</tbody></table>"
            )

        return "\n".join(parts)


class ScheduleStatusReport(BaseReportGenerator):
    """Report on backup schedule status."""

    def get_title(self) -> str:
        return "Schedule Status Report"

    def get_data(self) -> Dict[str, Any]:
        """Get schedule status data."""
        schedules = self.db.query(Schedule).all()

        schedule_list = []
        enabled_count = 0
        disabled_count = 0

        for schedule in schedules:
            if schedule.enabled:
                enabled_count += 1
            else:
                disabled_count += 1

            # Get target info
            if schedule.vm_id:
                vm = self.db.query(VM).filter(VM.id == schedule.vm_id).first()
                target = vm.name if vm else schedule.vm_id
                target_type = "VM"
            elif schedule.vm_group_id:
                target = schedule.vm_group_id
                target_type = "Group"
            else:
                target = "None"
                target_type = "N/A"

            schedule_list.append(
                {
                    "name": schedule.name,
                    "target": target,
                    "target_type": target_type,
                    "cron": schedule.cron_expression,
                    "backup_type": schedule.backup_type or "full",
                    "enabled": schedule.enabled,
                    "last_run": schedule.last_run_at,
                    "next_run": schedule.next_run_at,
                    "retention_days": schedule.retention_days,
                }
            )

        return {
            "total": len(schedules),
            "enabled": enabled_count,
            "disabled": disabled_count,
            "schedules": sorted(
                schedule_list, key=lambda x: (not x["enabled"], x["name"])
            ),
        }

    def build_pdf_content(self, data: Dict[str, Any]) -> List:
        """Build PDF content for schedule status."""
        elements = []

        # Summary
        elements.append(Paragraph("Summary", self.styles["SectionHeader"]))
        elements.append(
            Paragraph(
                f"Total schedules: <b>{data['total']}</b> | "
                f"Enabled: <b>{data['enabled']}</b> | "
                f"Disabled: <b>{data['disabled']}</b>",
                self.styles["SummaryText"],
            )
        )
        elements.append(Spacer(1, 15))

        # Schedule list
        elements.append(Paragraph("Schedule Details", self.styles["SectionHeader"]))
        table_data = [
            ["Name", "Target", "Cron", "Type", "Status", "Last Run", "Next Run"]
        ]
        for s in data["schedules"]:
            table_data.append(
                [
                    s["name"][:20],
                    s["target"][:15],
                    s["cron"],
                    s["backup_type"],
                    "Enabled" if s["enabled"] else "Disabled",
                    format_datetime(s["last_run"])[:10] if s["last_run"] else "Never",
                    format_datetime(s["next_run"])[:10] if s["next_run"] else "N/A",
                ]
            )
        elements.append(self._create_table(table_data, [80, 70, 70, 50, 55, 65, 65]))

        return elements

    def build_csv_content(self, data: Dict[str, Any]) -> List[List[str]]:
        """Build CSV content for schedule status."""
        rows = [
            ["Schedule Status Report"],
            [f"Generated: {format_datetime(datetime.utcnow())}"],
            [],
            ["Summary"],
            ["Total Schedules", str(data["total"])],
            ["Enabled", str(data["enabled"])],
            ["Disabled", str(data["disabled"])],
            [],
            [
                "Name",
                "Target",
                "Target Type",
                "Cron",
                "Backup Type",
                "Enabled",
                "Last Run",
                "Next Run",
                "Retention Days",
            ],
        ]
        for s in data["schedules"]:
            rows.append(
                [
                    s["name"],
                    s["target"],
                    s["target_type"],
                    s["cron"],
                    s["backup_type"],
                    "Yes" if s["enabled"] else "No",
                    format_datetime(s["last_run"]) if s["last_run"] else "Never",
                    format_datetime(s["next_run"]) if s["next_run"] else "N/A",
                    str(s["retention_days"]),
                ]
            )
        return rows

    def build_html_content(self, data: Dict[str, Any]) -> str:
        """Build HTML content for schedule status report."""
        parts = []

        # Summary box
        parts.append(
            f'<div class="summary">'
            f"<strong>Total Schedules:</strong> {data['total']} &nbsp;|&nbsp; "
            f"<strong>Enabled:</strong> {data['enabled']} &nbsp;|&nbsp; "
            f"<strong>Disabled:</strong> {data['disabled']}"
            f"</div>"
        )

        # Schedule details
        if data["schedules"]:
            parts.append("<h2>Schedule Details</h2>")
            sched_rows = "".join(
                f"<tr>"
                f"<td>{s['name']}</td>"
                f"<td>{s['target']}</td>"
                f"<td>{s['target_type']}</td>"
                f"<td>{s['cron']}</td>"
                f"<td>{s['backup_type'].capitalize()}</td>"
                f"<td>{'Enabled' if s['enabled'] else 'Disabled'}</td>"
                f"<td>{format_datetime(s['last_run']) if s['last_run'] else 'Never'}</td>"
                f"<td>{format_datetime(s['next_run']) if s['next_run'] else 'N/A'}</td>"
                f"<td>{s['retention_days']}</td>"
                f"</tr>"
                for s in data["schedules"]
            )
            parts.append(
                f"<table><thead><tr>"
                f"<th>Name</th><th>Target</th><th>Target Type</th><th>Schedule</th>"
                f"<th>Backup Type</th><th>Status</th><th>Last Run</th><th>Next Run</th>"
                f"<th>Retention (days)</th>"
                f"</tr></thead><tbody>{sched_rows}</tbody></table>"
            )

        return "\n".join(parts)


class StorageUsageReport(BaseReportGenerator):
    """Report on backup storage usage."""

    def get_title(self) -> str:
        return "Storage Usage Report"

    def get_data(self) -> Dict[str, Any]:
        """Get storage usage data."""
        backups = (
            self.db.query(Backup)
            .filter(
                Backup.status == "completed",
                Backup.size_bytes.isnot(None),
            )
            .all()
        )

        total_size = sum(b.size_bytes for b in backups if b.size_bytes)

        # By VM
        by_vm = {}
        for backup in backups:
            vm = self.db.query(VM).filter(VM.id == backup.vm_id).first()
            vm_name = vm.name if vm else backup.vm_id
            if vm_name not in by_vm:
                by_vm[vm_name] = {"size": 0, "count": 0}
            by_vm[vm_name]["size"] += backup.size_bytes or 0
            by_vm[vm_name]["count"] += 1

        # By agent
        by_agent = {}
        for backup in backups:
            vm = self.db.query(VM).filter(VM.id == backup.vm_id).first()
            if vm:
                agent = self.db.query(Agent).filter(Agent.id == vm.agent_id).first()
                agent_name = agent.get_display_name() if agent else "Unknown"
            else:
                agent_name = "Unknown"
            if agent_name not in by_agent:
                by_agent[agent_name] = {"size": 0, "count": 0}
            by_agent[agent_name]["size"] += backup.size_bytes or 0
            by_agent[agent_name]["count"] += 1

        # By type
        by_type = {}
        for backup in backups:
            btype = backup.backup_type or "full"
            if btype not in by_type:
                by_type[btype] = {"size": 0, "count": 0}
            by_type[btype]["size"] += backup.size_bytes or 0
            by_type[btype]["count"] += 1

        return {
            "total_size": total_size,
            "backup_count": len(backups),
            "by_vm": sorted(by_vm.items(), key=lambda x: -x[1]["size"]),
            "by_agent": sorted(by_agent.items(), key=lambda x: -x[1]["size"]),
            "by_type": by_type,
        }

    def build_pdf_content(self, data: Dict[str, Any]) -> List:
        """Build PDF content for storage usage."""
        elements = []

        # Summary
        elements.append(Paragraph("Summary", self.styles["SectionHeader"]))
        elements.append(
            Paragraph(
                f"Total storage used: <b>{format_bytes(data['total_size'])}</b> | "
                f"Total backups: <b>{data['backup_count']}</b>",
                self.styles["SummaryText"],
            )
        )
        elements.append(Spacer(1, 15))

        # By type
        elements.append(
            Paragraph("Storage by Backup Type", self.styles["SectionHeader"])
        )
        table_data = [["Type", "Size", "Count"]]
        for btype, stats in data["by_type"].items():
            table_data.append(
                [btype.capitalize(), format_bytes(stats["size"]), str(stats["count"])]
            )
        elements.append(self._create_table(table_data, [150, 100, 80]))
        elements.append(Spacer(1, 15))

        # By agent
        elements.append(Paragraph("Storage by Agent", self.styles["SectionHeader"]))
        table_data = [["Agent", "Size", "Backup Count"]]
        for agent_name, stats in data["by_agent"]:
            table_data.append(
                [agent_name[:25], format_bytes(stats["size"]), str(stats["count"])]
            )
        elements.append(self._create_table(table_data, [180, 100, 80]))
        elements.append(Spacer(1, 15))

        # Top VMs by storage
        elements.append(
            Paragraph("Top VMs by Storage Usage", self.styles["SectionHeader"])
        )
        table_data = [["VM Name", "Size", "Backup Count"]]
        for vm_name, stats in data["by_vm"][:15]:
            table_data.append(
                [vm_name[:30], format_bytes(stats["size"]), str(stats["count"])]
            )
        elements.append(self._create_table(table_data, [200, 100, 80]))

        return elements

    def build_csv_content(self, data: Dict[str, Any]) -> List[List[str]]:
        """Build CSV content for storage usage."""
        rows = [
            ["Storage Usage Report"],
            [f"Generated: {format_datetime(datetime.utcnow())}"],
            [],
            ["Summary"],
            ["Total Storage", format_bytes(data["total_size"])],
            ["Total Backups", str(data["backup_count"])],
            [],
            ["Storage by VM"],
            ["VM Name", "Size (bytes)", "Size (formatted)", "Backup Count"],
        ]
        for vm_name, stats in data["by_vm"]:
            rows.append(
                [
                    vm_name,
                    str(stats["size"]),
                    format_bytes(stats["size"]),
                    str(stats["count"]),
                ]
            )
        return rows

    def build_html_content(self, data: Dict[str, Any]) -> str:
        """Build HTML content for storage usage report."""
        parts = []

        # Summary box
        parts.append(
            f'<div class="summary">'
            f"<strong>Total Storage:</strong> {format_bytes(data['total_size'])} &nbsp;|&nbsp; "
            f"<strong>Total Backups:</strong> {data['backup_count']}"
            f"</div>"
        )

        # By type
        if data["by_type"]:
            parts.append("<h2>Storage by Backup Type</h2>")
            type_rows = "".join(
                f"<tr><td>{btype.capitalize()}</td>"
                f"<td>{format_bytes(stats['size'])}</td>"
                f"<td>{stats['count']}</td></tr>"
                for btype, stats in data["by_type"].items()
            )
            parts.append(
                f"<table><thead><tr><th>Type</th><th>Size</th><th>Count</th></tr></thead>"
                f"<tbody>{type_rows}</tbody></table>"
            )

        # By agent
        if data["by_agent"]:
            parts.append("<h2>Storage by Agent</h2>")
            agent_rows = "".join(
                f"<tr><td>{agent_name}</td>"
                f"<td>{format_bytes(stats['size'])}</td>"
                f"<td>{stats['count']}</td></tr>"
                for agent_name, stats in data["by_agent"]
            )
            parts.append(
                f"<table><thead><tr><th>Agent</th><th>Size</th><th>Backup Count</th></tr></thead>"
                f"<tbody>{agent_rows}</tbody></table>"
            )

        # By VM (top 15)
        if data["by_vm"]:
            parts.append("<h2>Top VMs by Storage Usage</h2>")
            vm_rows = "".join(
                f"<tr><td>{vm_name}</td>"
                f"<td>{format_bytes(stats['size'])}</td>"
                f"<td>{stats['count']}</td></tr>"
                for vm_name, stats in data["by_vm"][:15]
            )
            parts.append(
                f"<table><thead><tr><th>VM Name</th><th>Size</th><th>Backup Count</th></tr></thead>"
                f"<tbody>{vm_rows}</tbody></table>"
            )

        return "\n".join(parts)


class AgentHealthReport(BaseReportGenerator):
    """Report on agent health and status."""

    def get_title(self) -> str:
        return "Agent Health Report"

    def get_data(self) -> Dict[str, Any]:
        """Get agent health data."""
        agents = self.db.query(Agent).all()

        agent_list = []
        online_count = 0
        offline_count = 0

        for agent in agents:
            if agent.status == "online":
                online_count += 1
            else:
                offline_count += 1

            # Count VMs
            vm_count = self.db.query(VM).filter(VM.agent_id == agent.id).count()

            # Recent backup stats
            recent_backups = (
                self.db.query(Backup)
                .join(VM)
                .filter(
                    VM.agent_id == agent.id,
                    Backup.created_at >= self.start_date,
                )
                .all()
            )

            completed = len([b for b in recent_backups if b.status == "completed"])
            failed = len([b for b in recent_backups if b.status == "failed"])

            agent_list.append(
                {
                    "hostname": agent.get_display_name(),
                    "status": agent.status,
                    "ip_address": agent.ip_address or "N/A",
                    "version": agent.version or "Unknown",
                    "platform": agent.platform or "Unknown",
                    "last_heartbeat": agent.last_heartbeat,
                    "vm_count": vm_count,
                    "recent_completed": completed,
                    "recent_failed": failed,
                }
            )

        return {
            "total": len(agents),
            "online": online_count,
            "offline": offline_count,
            "agents": sorted(
                agent_list, key=lambda x: (x["status"] != "online", x["hostname"])
            ),
        }

    def build_pdf_content(self, data: Dict[str, Any]) -> List:
        """Build PDF content for agent health."""
        elements = []

        # Summary
        elements.append(Paragraph("Summary", self.styles["SectionHeader"]))
        elements.append(
            Paragraph(
                f"Total agents: <b>{data['total']}</b> | "
                f"Online: <b>{data['online']}</b> | "
                f"Offline: <b>{data['offline']}</b>",
                self.styles["SummaryText"],
            )
        )
        elements.append(Spacer(1, 15))

        # Agent list
        elements.append(Paragraph("Agent Details", self.styles["SectionHeader"]))
        table_data = [
            ["Hostname", "Status", "IP", "Version", "VMs", "Last Heartbeat", "OK/Fail"]
        ]
        for a in data["agents"]:
            table_data.append(
                [
                    a["hostname"][:20],
                    a["status"].upper(),
                    a["ip_address"][:15],
                    a["version"][:10],
                    str(a["vm_count"]),
                    (
                        format_datetime(a["last_heartbeat"])[:16]
                        if a["last_heartbeat"]
                        else "Never"
                    ),
                    f"{a['recent_completed']}/{a['recent_failed']}",
                ]
            )
        elements.append(self._create_table(table_data, [85, 50, 70, 55, 30, 90, 50]))

        return elements

    def build_csv_content(self, data: Dict[str, Any]) -> List[List[str]]:
        """Build CSV content for agent health."""
        rows = [
            ["Agent Health Report"],
            [f"Generated: {format_datetime(datetime.utcnow())}"],
            [
                f"Period: {format_datetime(self.start_date)} to {format_datetime(self.end_date)}"
            ],
            [],
            ["Summary"],
            ["Total Agents", str(data["total"])],
            ["Online", str(data["online"])],
            ["Offline", str(data["offline"])],
            [],
            [
                "Hostname",
                "Status",
                "IP Address",
                "Version",
                "Platform",
                "VM Count",
                "Last Heartbeat",
                "Recent Completed",
                "Recent Failed",
            ],
        ]
        for a in data["agents"]:
            rows.append(
                [
                    a["hostname"],
                    a["status"],
                    a["ip_address"],
                    a["version"],
                    a["platform"],
                    str(a["vm_count"]),
                    (
                        format_datetime(a["last_heartbeat"])
                        if a["last_heartbeat"]
                        else "Never"
                    ),
                    str(a["recent_completed"]),
                    str(a["recent_failed"]),
                ]
            )
        return rows

    def build_html_content(self, data: Dict[str, Any]) -> str:
        """Build HTML content for agent health report."""
        parts = []

        # Summary box
        parts.append(
            f'<div class="summary">'
            f"<strong>Total Agents:</strong> {data['total']} &nbsp;|&nbsp; "
            f"<strong>Online:</strong> {data['online']} &nbsp;|&nbsp; "
            f"<strong>Offline:</strong> {data['offline']}"
            f"</div>"
        )

        # Agent details
        if data["agents"]:
            parts.append("<h2>Agent Details</h2>")
            agent_rows = "".join(
                f"<tr>"
                f"<td>{a['hostname']}</td>"
                f"<td>{a['status'].upper()}</td>"
                f"<td>{a['ip_address']}</td>"
                f"<td>{a['version']}</td>"
                f"<td>{a['platform']}</td>"
                f"<td>{a['vm_count']}</td>"
                f"<td>{format_datetime(a['last_heartbeat']) if a['last_heartbeat'] else 'Never'}</td>"
                f"<td>{a['recent_completed']}</td>"
                f"<td>{a['recent_failed']}</td>"
                f"</tr>"
                for a in data["agents"]
            )
            parts.append(
                f"<table><thead><tr>"
                f"<th>Hostname</th><th>Status</th><th>IP Address</th><th>Version</th>"
                f"<th>Platform</th><th>VMs</th><th>Last Heartbeat</th>"
                f"<th>Recent OK</th><th>Recent Failed</th>"
                f"</tr></thead><tbody>{agent_rows}</tbody></table>"
            )

        return "\n".join(parts)


# Registry of report generators
REPORT_GENERATORS = {
    "failed_backups": FailedBackupsReport,
    "backup_summary": BackupSummaryReport,
    "vm_inventory": VMInventoryReport,
    "schedule_status": ScheduleStatusReport,
    "storage_usage": StorageUsageReport,
    "agent_health": AgentHealthReport,
}


def generate_report(report: Report, db: Session) -> Tuple[bytes, str]:
    """
    Generate a report using the appropriate generator.

    Args:
        report: Report configuration from database
        db: Database session

    Returns:
        Tuple of (content bytes, filename)

    Raises:
        ValueError: If report type is not supported
    """
    generator_class = REPORT_GENERATORS.get(report.report_type)
    if not generator_class:
        raise ValueError(f"Unsupported report type: {report.report_type}")

    generator = generator_class(report, db)
    return generator.generate()
