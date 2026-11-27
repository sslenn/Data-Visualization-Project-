"""
Cyber Security Attack Analysis - cleaning, visualizations, static exports & dashboard
Run from the Data-Visualization Project folder:  python analysis.py
Needs: pandas, plotly, matplotlib

Reads:
  Datasets/cybersecurity_attacks.csv

Writes:
  Datasets/cleaned_cybersecurity_attacks.csv
  charts/*.html                              (10 interactive Plotly charts)
  exports/*.png                              (10 high-DPI static PNG charts)
  exports/cybersecurity_attack_charts.pdf    (multi-page PDF of all 10 charts)
  dashboard.html                             (interactive KPI + filtered dashboard)
"""
from __future__ import annotations

import datetime
import json
import re
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.dates as mdates
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

# ----------------------------------------------------------------- 0. PATHS & PALETTE
BASE = Path(__file__).resolve().parent
DATA_DIR = BASE / "Datasets"
RAW_CSV = DATA_DIR / "cybersecurity_attacks.csv"
CLEAN_CSV = DATA_DIR / "cleaned_cybersecurity_attacks.csv"
CHART_DIR = BASE / "charts"
EXPORT_DIR = BASE / "exports"
DASHBOARD_HTML = BASE / "dashboard.html"

CHART_DIR.mkdir(exist_ok=True)
EXPORT_DIR.mkdir(exist_ok=True)

# ----------------------------------------------------------------- COLOR SYSTEM
# Aligned with Week 3-4 Colour Theory & Week 7 Accessibility:
#   - Distinct Hue (Okabe-Ito, colorblind-safe) exclusively for Attack Type
#   - Monochromatic Light-to-Dark Purple (ColorBrewer Purples) exclusively for ordered Severity Level
#   - Saturation hierarchy for Action Taken (low-saturation Logged, vivid focal Ignored)
#   - Neutral Slate exclusively for aggregate "All Events" totals (never collides with DDoS blue)
ATTACK_ORDER = ["DDoS", "Malware", "Intrusion"]
ATTACK_COLORS = {
    "DDoS": "#0072B2",       # Okabe-Ito Blue
    "Malware": "#D55E00",    # Okabe-Ito Vermilion
    "Intrusion": "#009E73",  # Okabe-Ito Bluish Green
}
ATTACK_DASH = {
    "DDoS": "solid",
    "Malware": "dash",
    "Intrusion": "dot",
}
ATTACK_MPL_LS = {
    "DDoS": "-",
    "Malware": "--",
    "Intrusion": "-.",
}

# Monochromatic light-to-dark scale for ordered Severity Level (ColorBrewer Purples)
SEV_ORDER = ["Low", "Medium", "High"]
SEV_COLORS = {
    "Low": "#DADAEB",
    "Medium": "#9E9AC8",
    "High": "#54278F",
}

# Action Taken: deliberate saturation & semantic contrast (no collision with Attack Type)
ACTION_ORDER = ["Blocked", "Logged", "Ignored"]
ACTION_COLORS = {
    "Blocked": "#2A7B88",   # Deep Teal (defended / positive)
    "Logged": "#94A3B8",    # Low-saturation Slate Gray (passive / background)
    "Ignored": "#C0264B",   # Vivid Crimson-Magenta (focal alert for Key Finding)
}

NEUTRAL_BAR = "#475569"     # Neutral Slate for aggregate "All Events" charts
KDE_COLOR = "#B45309"       # Warm Amber-Brown for KDE curve (distinct from Malware)

DAY_ORDER = [
    "Monday", "Tuesday", "Wednesday", "Thursday",
    "Friday", "Saturday", "Sunday",
]

FLAG_MAP = {
    "Malware Indicators": "IoC Detected",
    "Alerts/Warnings": "Alert Triggered",
    "Proxy Information": "Proxy Used",
    "Firewall Logs": "Firewall Log",
    "IDS/IPS Alerts": "IDS/IPS Alert",
}
FLAG_COLS = list(FLAG_MAP.values())


def parse_os(ua: str) -> str:
    if re.search(r"Windows", ua, re.I):
        return "Windows"
    if re.search(r"iPhone|iPad|iPod", ua, re.I):
        return "iOS"
    if re.search(r"Android", ua, re.I):
        return "Android"
    if re.search(r"Macintosh|Mac OS", ua, re.I):
        return "macOS"
    if re.search(r"Linux|X11", ua, re.I):
        return "Linux"
    return "Other"


def parse_browser(ua: str) -> str:
    if re.search(r"MSIE|Trident", ua, re.I):
        return "Internet Explorer"
    if re.search(r"Opera", ua, re.I):
        return "Opera"
    if re.search(r"FxiOS|Firefox", ua, re.I):
        return "Firefox"
    if re.search(r"CriOS|Chrome", ua, re.I):
        return "Chrome"
    if re.search(r"Safari", ua, re.I):
        return "Safari"
    return "Other"


def clean_dataset() -> pd.DataFrame:
    # ------------------------------------------------------------- 1. PROFILE
    df = pd.read_csv(RAW_CSV)
    n_rows = len(df)
    print(f"Shape: {df.shape}")
    print(f"Duplicate rows (raw): {df.duplicated().sum()}")
    missing = df.isna().sum()
    print("Columns with missing values:\n", missing[missing > 0], "\n")

    # --------------------------------------------------------------- 2. CLEAN
    # 2a. Missing values: do NOT impute. A blank means "not present", so recode to
    #     a yes/no flag and keep the non-PII raw columns alongside.
    for raw_col, flag_col in FLAG_MAP.items():
        df[flag_col] = df[raw_col].notna().map({True: "Yes", False: "No"})
        yes, no = (df[flag_col] == "Yes").sum(), (df[flag_col] == "No").sum()
        assert yes + no == n_rows, f"{flag_col}: yes+no != {n_rows}"
        assert yes == df[raw_col].notna().sum(), f"{flag_col}: yes != present count"
        print(f"{flag_col}: Yes={yes:,}  No={no:,}")

    # 2b. Formats & parsing
    df["Timestamp"] = pd.to_datetime(df["Timestamp"])
    df["Severity Level"] = pd.Categorical(
        df["Severity Level"].astype(str).str.strip(),
        categories=SEV_ORDER,
        ordered=True,
    )
    for col in [
        "Attack Type", "Action Taken", "Protocol",
        "Traffic Type", "Network Segment", "Log Source",
    ]:
        df[col] = df[col].astype(str).str.strip()

    geo = df["Geo-location Data"].str.rsplit(",", n=1, expand=True)
    df["City"] = geo[0].str.strip()
    df["State"] = geo[1].str.strip()

    # Parse Device Information user-agent into OS and Browser Family before dropping raw string
    ua_series = df["Device Information"].astype(str)
    df["Device OS"] = ua_series.map(parse_os)
    df["Browser Family"] = ua_series.map(parse_browser)

    # Re-check duplicates after type conversions (proposal Section 3)
    dups_after = df.duplicated().sum()
    print(f"\nDuplicate rows (post-conversion): {dups_after}")
    assert dups_after == 0, f"Unexpected duplicates after conversion: {dups_after}"

    # 2c. Derived fields
    df["Year"] = df["Timestamp"].dt.year
    df["Quarter"] = df["Timestamp"].dt.to_period("Q").astype(str)
    df["Month"] = df["Timestamp"].dt.to_period("M").dt.to_timestamp()
    df["DayOfWeek"] = df["Timestamp"].dt.day_name()
    df["Hour"] = df["Timestamp"].dt.hour
    df["Blocked"] = (df["Action Taken"] == "Blocked").astype(int)
    df["Anomaly Band"] = pd.cut(
        df["Anomaly Scores"],
        [-0.01, 25, 50, 75, 100],
        labels=["0-25", "25-50", "50-75", "75-100"],
    )
    df["High Anomaly"] = (df["Anomaly Scores"] >= 75).map({True: "Yes", False: "No"})
    df["Packet Size Band"] = pd.cut(
        df["Packet Length"],
        [0, 500, 1000, 1500],
        labels=["64-500", "501-1000", "1001-1500"],
    )

    # 2d. Range checks (flag, do not delete)
    print(
        "Ports out of range:",
        ((df["Source Port"] > 65535) | (df["Destination Port"] > 65535)).sum(),
    )
    print(
        "Packet length out of 64-1500:",
        (~df["Packet Length"].between(64, 1500)).sum(),
    )
    print(
        "Anomaly score out of 0-100:",
        (~df["Anomaly Scores"].between(0, 100)).sum(),
    )
    print(
        "High Anomaly (>=75) count:",
        (df["High Anomaly"] == "Yes").sum(),
    )

    # 2e. Drop near-unique / privacy-sensitive fields, then save
    drop_cols = [
        "Payload Data",
        "Source IP Address",
        "Destination IP Address",
        "User Information",
        "Device Information",
        "Proxy Information",
    ]
    clean = df.drop(columns=drop_cols)
    assert len(clean) == n_rows
    clean.to_csv(CLEAN_CSV, index=False)
    print(f"\nSaved {CLEAN_CSV.relative_to(BASE)} ({len(clean):,} rows, {clean.shape[1]} cols)")
    return clean


def style_plotly(fig: go.Figure, show_legend: bool = True) -> go.Figure:
    fig.update_layout(
        template="plotly_white",
        font=dict(family="Segoe UI, Arial, sans-serif", size=13, color="#1F2937"),
        title=dict(font=dict(size=16, color="#111827"), x=0.02, xanchor="left", y=0.96),
        showlegend=show_legend,
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1.0,
            title_text="",
        ),
        margin=dict(l=65, r=30, t=95, b=60),
    )
    fig.update_xaxes(showline=True, linewidth=1, linecolor="#9CA3AF", mirror=False)
    fig.update_yaxes(showline=True, linewidth=1, linecolor="#9CA3AF", mirror=False)
    return fig


def save_plotly(fig: go.Figure, name: str) -> None:
    fig.write_html(CHART_DIR / f"{name}.html", include_plotlyjs="cdn")


def build_plotly_charts(clean: pd.DataFrame) -> None:
    # 1. Monthly attacks by type (y-axis starts at 0 for Lie Factor = 1; distinct line styles + hue)
    monthly = clean.groupby(["Month", "Attack Type"]).size().reset_index(name="Events")
    fig = px.line(
        monthly,
        x="Month",
        y="Events",
        color="Attack Type",
        line_dash="Attack Type",
        category_orders={"Attack Type": ATTACK_ORDER},
        color_discrete_map=ATTACK_COLORS,
        line_dash_map=ATTACK_DASH,
        labels={"Month": "Month (Jan 2020 – Oct 2023)", "Events": "Attack Events (count)"},
        title="Monthly attacks stay steady (~280–320/type) until partial Oct 2023",
    )
    fig.update_yaxes(range=[0, monthly["Events"].max() * 1.15])
    fig.add_vrect(
        x0="2023-09-20",
        x1="2023-10-15",
        fillcolor="#E69F00",
        opacity=0.22,
        layer="below",
        line_width=0,
        label=dict(
            text="Partial Oct 2023<br>(ends Oct 11, 296 rows)",
            textposition="top left",
            font=dict(size=11, color="#92400E"),
        ),
    )
    save_plotly(style_plotly(fig, show_legend=True), "01_monthly_trend")

    # 2. Day of week x hour heatmap
    heat = (
        clean.pivot_table(
            index="DayOfWeek", columns="Hour", values="Attack Type", aggfunc="count"
        ).reindex(DAY_ORDER)
    )
    fig = px.imshow(
        heat,
        aspect="auto",
        color_continuous_scale="Blues",
        labels=dict(x="Hour of Day (0–23 UTC)", y="Day of Week", color="Events (count)"),
        title="Attack activity is evenly distributed across days and hours",
    )
    save_plotly(style_plotly(fig, show_legend=False), "02_heatmap_day_hour")

    # 3. Attack type frequency (horizontal bar, starts at 0, no redundant legend)
    by_type = clean["Attack Type"].value_counts().reindex(ATTACK_ORDER).reset_index()
    by_type.columns = ["Attack Type", "Events"]
    fig = px.bar(
        by_type,
        x="Events",
        y="Attack Type",
        color="Attack Type",
        orientation="h",
        category_orders={"Attack Type": ATTACK_ORDER},
        color_discrete_map=ATTACK_COLORS,
        text="Events",
        labels={"Events": "Attack Events (count)", "Attack Type": "Attack Type"},
        title="DDoS, Malware, and Intrusion occur at nearly identical frequencies (~33% each)",
    )
    fig.update_traces(texttemplate="%{text:,}", textposition="outside")
    fig.update_xaxes(range=[0, by_type["Events"].max() * 1.15])
    save_plotly(style_plotly(fig, show_legend=False), "03_attack_type_bar")

    # 4. Severity by attack type (stacked, ordered light-to-dark severity scale)
    sev = (
        clean.groupby(["Attack Type", "Severity Level"], observed=True)
        .size()
        .reset_index(name="Events")
    )
    fig = px.bar(
        sev,
        x="Attack Type",
        y="Events",
        color="Severity Level",
        barmode="stack",
        category_orders={"Attack Type": ATTACK_ORDER, "Severity Level": SEV_ORDER},
        color_discrete_map=SEV_COLORS,
        labels={"Attack Type": "Attack Type", "Events": "Attack Events (count)"},
        title="Severity levels split evenly (~33% Low, Medium, High) across every attack type",
    )
    fig.update_yaxes(range=[0, clean["Attack Type"].value_counts().max() * 1.12])
    save_plotly(style_plotly(fig, show_legend=True), "04_severity_stacked")

    # 5. Treemap: network segment > attack type
    tree = (
        clean.groupby(["Network Segment", "Attack Type"])
        .size()
        .reset_index(name="Events")
    )
    fig = px.treemap(
        tree,
        path=["Network Segment", "Attack Type"],
        values="Events",
        color="Attack Type",
        color_discrete_map={**ATTACK_COLORS, "(?)": "#E5E7EB"},
        title="All three network segments face balanced exposure across attack types",
    )
    fig.update_traces(textinfo="label+value+percent parent")
    save_plotly(style_plotly(fig, show_legend=False), "05_treemap_segment")

    # 6. Bubble: protocol x traffic type (high-contrast text + balanced color range)
    bub = (
        clean.groupby(["Protocol", "Traffic Type"])
        .size()
        .reset_index(name="Events")
    )
    mid_val = bub["Events"].median()
    text_colors = ["white" if v >= mid_val else "#111827" for v in bub["Events"]]
    fig = px.scatter(
        bub,
        x="Protocol",
        y="Traffic Type",
        size="Events",
        color="Events",
        color_continuous_scale="Blues",
        range_color=[bub["Events"].min() * 0.92, bub["Events"].max() * 1.02],
        size_max=58,
        text="Events",
        labels={
            "Protocol": "Network Protocol",
            "Traffic Type": "Traffic Type",
            "Events": "Events (count)",
        },
        title="Attacks spread uniformly across TCP/UDP/ICMP and HTTP/DNS/FTP (~4,400 each)",
    )
    fig.update_traces(
        texttemplate="%{text:,}",
        textposition="middle center",
        textfont=dict(color=text_colors, size=12),
        marker=dict(line=dict(width=1.2, color="#1E3A8A")),
    )
    save_plotly(style_plotly(fig, show_legend=False), "06_bubble_protocol_traffic")

    # 7. KEY FINDING: action taken by severity (share of events)
    act = (
        pd.crosstab(clean["Severity Level"], clean["Action Taken"], normalize="index")
        .mul(100)
        .round(1)
    )
    act_long = act.reset_index().melt(
        id_vars="Severity Level", var_name="Action Taken", value_name="Percent"
    )
    fig = px.bar(
        act_long,
        x="Severity Level",
        y="Percent",
        color="Action Taken",
        barmode="group",
        category_orders={"Severity Level": SEV_ORDER, "Action Taken": ACTION_ORDER},
        color_discrete_map=ACTION_COLORS,
        text="Percent",
        labels={
            "Severity Level": "Severity Level",
            "Percent": "Share of Events (%)",
        },
        title="Key Finding: Blocking rate (~34%) does not increase for High-severity attacks",
    )
    fig.update_traces(texttemplate="%{text:.1f}%", textposition="outside")
    fig.update_yaxes(range=[0, 44], ticksuffix="%")
    fig.add_annotation(
        x="High",
        y=33.3,
        text="33.3% of High-severity<br>attacks are Ignored",
        showarrow=True,
        arrowhead=2,
        ax=45,
        ay=-45,
        font=dict(size=11, color="#9D174D"),
        bgcolor="#FDF2F8",
        bordercolor="#CC79A7",
    )
    save_plotly(style_plotly(fig, show_legend=True), "07_action_by_severity")

    # 8. Geography: events per state (neutral slate so it does not collide with DDoS blue)
    state = clean["State"].value_counts().reset_index()
    state.columns = ["State", "Events"]
    fig = px.bar(
        state,
        x="Events",
        y="State",
        orientation="h",
        color_discrete_sequence=[NEUTRAL_BAR],
        labels={"Events": "Attack Events (count)", "State": "Indian State"},
        title="Events span 28 Indian states evenly (1,373 to 1,498 events per state)",
    )
    fig.update_layout(yaxis={"categoryorder": "total ascending"}, height=820)
    fig.update_xaxes(range=[0, state["Events"].max() * 1.08])
    save_plotly(style_plotly(fig, show_legend=False), "08_events_by_state")

    # 9. Box plot: Anomaly score distribution by attack type & severity (Week 7 Section VI)
    fig = px.box(
        clean,
        x="Attack Type",
        y="Anomaly Scores",
        color="Severity Level",
        category_orders={"Attack Type": ATTACK_ORDER, "Severity Level": SEV_ORDER},
        color_discrete_map=SEV_COLORS,
        labels={
            "Attack Type": "Attack Type",
            "Anomaly Scores": "Anomaly Score (0–100 scale)",
        },
        title="Anomaly scores average ~50 across all attack types and severity levels",
    )
    fig.update_yaxes(range=[0, 108])
    fig.add_hline(
        y=75,
        line_dash="dot",
        line_color="#D55E00",
        label=dict(
            text="High-Anomaly Threshold (≥75)",
            textposition="end",
            font=dict(size=11, color="#D55E00"),
        ),
    )
    save_plotly(style_plotly(fig, show_legend=True), "09_anomaly_scores_by_type_severity")

    # 10. Detection flags trigger rates by severity (Proposal Section 6 Finding 5)
    flag_rows = []
    for sev_lvl in SEV_ORDER:
        sub = clean[clean["Severity Level"] == sev_lvl]
        for fc in FLAG_COLS:
            pct = (sub[fc] == "Yes").mean() * 100
            flag_rows.append({"Detection Flag": fc, "Severity Level": sev_lvl, "Present (%)": round(pct, 1)})
    flag_df = pd.DataFrame(flag_rows)
    fig = px.bar(
        flag_df,
        x="Detection Flag",
        y="Present (%)",
        color="Severity Level",
        barmode="group",
        category_orders={"Severity Level": SEV_ORDER},
        color_discrete_map=SEV_COLORS,
        text="Present (%)",
        labels={"Detection Flag": "Detection Signal", "Present (%)": "Events with Signal Present (%)"},
        title="All five detection signals trigger on ~50% of events regardless of severity",
    )
    fig.update_traces(texttemplate="%{text:.1f}%", textposition="outside")
    fig.update_yaxes(range=[0, 62], ticksuffix="%")
    save_plotly(style_plotly(fig, show_legend=True), "10_detection_flags_by_severity")

    # 11. Histogram + KDE of Anomaly Scores (Week 7 Sections II & III: Uniform Distribution)
    scores = clean["Anomaly Scores"].values
    bins = np.arange(0, 105, 5)
    counts, edges = np.histogram(scores, bins=bins)
    centers = 0.5 * (edges[:-1] + edges[1:])
    # Smooth Gaussian KDE scaled to frequency (count per bin width = 5)
    grid = np.linspace(0, 100, 200)
    bw = 1.06 * scores.std(ddof=1) * (len(scores) ** (-1 / 5))
    # Subsample or bin-weighted KDE for speed on 40k rows
    kde_density = np.zeros_like(grid)
    for c, cnt in zip(centers, counts):
        kde_density += cnt * np.exp(-0.5 * ((grid - c) / bw) ** 2)
    kde_density = kde_density / (len(scores) * bw * np.sqrt(2 * np.pi))
    kde_scaled = kde_density * len(scores) * 5.0  # match bin width = 5 frequency scale

    fig = go.Figure()
    fig.add_trace(
        go.Bar(
            x=centers,
            y=counts,
            width=4.6,
            name="Histogram (bin width = 5)",
            marker_color=NEUTRAL_BAR,
            opacity=0.72,
        )
    )
    fig.add_trace(
        go.Scatter(
            x=grid,
            y=kde_scaled,
            mode="lines",
            name="Kernel Density Estimate (KDE)",
            line=dict(color=KDE_COLOR, width=2.8),
        )
    )
    fig.add_vline(
        x=float(scores.mean()),
        line_dash="dash",
        line_color="#111827",
        annotation_text=f"Mean = {scores.mean():.1f}",
        annotation_position="top right",
    )
    fig.update_layout(
        title="Anomaly scores follow a uniform (flat) distribution across 0–100 (bin width = 5)",
        xaxis_title="Anomaly Score (0–100 scale, bin width = 5)",
        yaxis_title="Frequency (number of events)",
        yaxis=dict(range=[0, max(counts) * 1.25]),
        xaxis=dict(range=[0, 100], dtick=10),
    )
    save_plotly(style_plotly(fig, show_legend=True), "11_anomaly_histogram_kde")


def _clean_ax(ax: plt.Axes, grid_axis: str = "y") -> None:
    """Apply Week 7 Principle 5 (Focus on content: remove chartjunk top/right spines, light grid)."""
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color("#6B7280")
    ax.spines["bottom"].set_color("#6B7280")
    if grid_axis:
        ax.grid(axis=grid_axis, linestyle="--", alpha=0.35, color="#9CA3AF")
        ax.set_axisbelow(True)


def build_static_exports(clean: pd.DataFrame) -> None:
    """Export all 11 charts as high-DPI PNGs and a combined multi-page PDF via Matplotlib."""
    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "axes.edgecolor": "#6B7280",
            "axes.linewidth": 0.9,
            "axes.titlesize": 13,
            "axes.titleweight": "bold",
            "axes.labelsize": 10.5,
            "xtick.labelsize": 9.5,
            "ytick.labelsize": 9.5,
            "legend.fontsize": 9.5,
            "figure.facecolor": "white",
            "axes.facecolor": "white",
        }
    )

    pdf_path = EXPORT_DIR / "cybersecurity_attack_charts.pdf"

    def save_fig(fig: plt.Figure, name: str, pdf: PdfPages) -> None:
        fig.tight_layout()
        fig.savefig(EXPORT_DIR / f"{name}.png", dpi=200, bbox_inches="tight")
        pdf.savefig(fig, bbox_inches="tight")
        plt.close(fig)

    with PdfPages(pdf_path) as pdf:
        meta = pdf.infodict()
        meta["Title"] = "Cyber Security Attack Analysis — Chart Pack"
        meta["Author"] = "Team 04 — Data Visualization"
        meta["CreationDate"] = datetime.datetime.today()

        # 1. Monthly trend (y-axis starts at 0 for Lie Factor = 1; distinct line styles + hue)
        monthly = clean.groupby(["Month", "Attack Type"]).size().unstack(fill_value=0)[ATTACK_ORDER]
        fig, ax = plt.subplots(figsize=(10.5, 5.0))
        for at in ATTACK_ORDER:
            ax.plot(
                monthly.index,
                monthly[at],
                label=at,
                color=ATTACK_COLORS[at],
                linestyle=ATTACK_MPL_LS[at],
                linewidth=2.1,
            )
        ax.axvspan(pd.Timestamp("2023-09-20"), pd.Timestamp("2023-10-15"), color="#E69F00", alpha=0.22)
        ax.annotate(
            "Partial Oct 2023\n(ends Oct 11, 296 rows)",
            xy=(pd.Timestamp("2023-10-01"), monthly.iloc[-1].mean()),
            xytext=(pd.Timestamp("2022-11-01"), 115),
            arrowprops=dict(arrowstyle="->", color="#92400E", lw=1.2),
            fontsize=9.5,
            color="#92400E",
            bbox=dict(boxstyle="round,pad=0.35", fc="#FFFBEB", ec="#E69F00"),
        )
        ax.set_ylim(0, monthly.values.max() * 1.18)
        ax.set_title("Monthly attacks stay steady (~280–320/type) until partial Oct 2023", loc="left", pad=28)
        ax.set_xlabel("Month (Jan 2020 – Oct 2023)")
        ax.set_ylabel("Attack Events (count)")
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%b %Y"))
        _clean_ax(ax, "y")
        ax.legend(frameon=False, ncol=3, loc="lower right", bbox_to_anchor=(1.0, 1.01))
        save_fig(fig, "01_monthly_trend", pdf)

        # 2. Heatmap day x hour
        heat = (
            clean.pivot_table(index="DayOfWeek", columns="Hour", values="Attack Type", aggfunc="count")
            .reindex(DAY_ORDER)
        )
        fig, ax = plt.subplots(figsize=(11, 4.7))
        im = ax.imshow(heat.values, aspect="auto", cmap="Blues")
        ax.set_xticks(range(24))
        ax.set_xticklabels(range(24))
        ax.set_yticks(range(len(DAY_ORDER)))
        ax.set_yticklabels(DAY_ORDER)
        ax.set_xlabel("Hour of Day (0–23 UTC)")
        ax.set_ylabel("Day of Week")
        ax.set_title("Attack activity is evenly distributed across days and hours", loc="left", pad=12)
        cbar = fig.colorbar(im, ax=ax, pad=0.02)
        cbar.set_label("Events (count)")
        save_fig(fig, "02_heatmap_day_hour", pdf)

        # 3. Horizontal bar: Attack type (starts at 0, no redundant legend)
        by_type = clean["Attack Type"].value_counts().reindex(ATTACK_ORDER)
        fig, ax = plt.subplots(figsize=(9.0, 4.3))
        bars = ax.barh(
            ATTACK_ORDER,
            by_type.values,
            color=[ATTACK_COLORS[a] for a in ATTACK_ORDER],
            height=0.55,
        )
        for bar, val in zip(bars, by_type.values):
            ax.text(val + 180, bar.get_y() + bar.get_height() / 2, f"{val:,}", va="center", fontsize=10, fontweight="bold")
        ax.set_xlim(0, by_type.max() * 1.15)
        ax.set_xlabel("Attack Events (count)")
        ax.set_ylabel("Attack Type")
        ax.set_title("DDoS, Malware, and Intrusion occur at nearly identical frequencies (~33% each)", loc="left", pad=12)
        _clean_ax(ax, "x")
        save_fig(fig, "03_attack_type_bar", pdf)

        # 4. Stacked bar: Severity by attack type (legend cleanly above plot, no overlap)
        sev = (
            clean.groupby(["Attack Type", "Severity Level"], observed=True)
            .size()
            .unstack(fill_value=0)
            .reindex(index=ATTACK_ORDER, columns=SEV_ORDER)
        )
        fig, ax = plt.subplots(figsize=(9.0, 5.2))
        bottom = np.zeros(len(ATTACK_ORDER))
        for s in SEV_ORDER:
            vals = sev[s].values
            ax.bar(ATTACK_ORDER, vals, bottom=bottom, label=s, color=SEV_COLORS[s], width=0.5)
            bottom += vals
        ax.set_ylim(0, bottom.max() * 1.12)
        ax.set_xlabel("Attack Type")
        ax.set_ylabel("Attack Events (count)")
        ax.set_title("Severity levels split evenly (~33% Low, Medium, High) across every attack type", loc="left", pad=28)
        _clean_ax(ax, "y")
        ax.legend(frameon=False, ncol=3, loc="lower right", bbox_to_anchor=(1.0, 1.01))
        save_fig(fig, "04_severity_stacked", pdf)

        # 5. Network segment x attack type (legend cleanly above plot, no overlap)
        seg = (
            clean.groupby(["Network Segment", "Attack Type"])
            .size()
            .unstack(fill_value=0)[ATTACK_ORDER]
        )
        fig, ax = plt.subplots(figsize=(9.0, 5.2))
        x = np.arange(len(seg.index))
        w = 0.25
        for i, at in enumerate(ATTACK_ORDER):
            ax.bar(x + (i - 1) * w, seg[at].values, width=w, label=at, color=ATTACK_COLORS[at])
        ax.set_xticks(x)
        ax.set_xticklabels(seg.index)
        ax.set_ylim(0, seg.values.max() * 1.15)
        ax.set_xlabel("Network Segment")
        ax.set_ylabel("Attack Events (count)")
        ax.set_title("All three network segments face balanced exposure across attack types", loc="left", pad=28)
        _clean_ax(ax, "y")
        ax.legend(frameon=False, ncol=3, loc="lower right", bbox_to_anchor=(1.0, 1.01))
        save_fig(fig, "05_treemap_segment", pdf)

        # 6. Bubble chart: Protocol x Traffic Type (accessible high-contrast text on every bubble)
        bub = clean.groupby(["Protocol", "Traffic Type"]).size().reset_index(name="Events")
        prots = sorted(bub["Protocol"].unique())
        trafs = sorted(bub["Traffic Type"].unique())
        px_map = {p: i for i, p in enumerate(prots)}
        py_map = {t: i for i, t in enumerate(trafs)}
        vmin = bub["Events"].min() * 0.92
        vmax = bub["Events"].max() * 1.02
        mid_v = (vmin + vmax) / 2.0
        fig, ax = plt.subplots(figsize=(8.6, 5.0))
        sc = ax.scatter(
            bub["Protocol"].map(px_map),
            bub["Traffic Type"].map(py_map),
            s=bub["Events"] * 0.48,
            c=bub["Events"],
            cmap="Blues",
            vmin=vmin,
            vmax=vmax,
            edgecolors="#1E3A8A",
            linewidth=1.3,
            alpha=0.95,
        )
        for _, row in bub.iterrows():
            txt_color = "white" if row["Events"] >= mid_v else "#111827"
            ax.text(
                px_map[row["Protocol"]],
                py_map[row["Traffic Type"]],
                f"{row['Events']:,}",
                ha="center",
                va="center",
                color=txt_color,
                fontsize=9.5,
                fontweight="bold",
            )
        ax.set_xticks(range(len(prots)))
        ax.set_xticklabels(prots)
        ax.set_yticks(range(len(trafs)))
        ax.set_yticklabels(trafs)
        ax.set_xlim(-0.5, len(prots) - 0.5)
        ax.set_ylim(-0.5, len(trafs) - 0.5)
        ax.set_xlabel("Network Protocol")
        ax.set_ylabel("Traffic Type")
        ax.set_title("Attacks spread uniformly across TCP/UDP/ICMP and HTTP/DNS/FTP (~4,400 each)", loc="left", pad=12)
        _clean_ax(ax, None)
        cbar = fig.colorbar(sc, ax=ax, pad=0.02)
        cbar.set_label("Events (count)")
        save_fig(fig, "06_bubble_protocol_traffic", pdf)

        # 7. Key Finding: Action taken by severity (with callout annotation + clean legend above)
        act = (
            pd.crosstab(clean["Severity Level"], clean["Action Taken"], normalize="index")
            .mul(100)
            .reindex(index=SEV_ORDER, columns=ACTION_ORDER)
        )
        fig, ax = plt.subplots(figsize=(9.2, 5.2))
        x = np.arange(len(SEV_ORDER))
        w = 0.25
        for i, ac in enumerate(ACTION_ORDER):
            vals = act[ac].values
            bars = ax.bar(x + (i - 1) * w, vals, width=w, label=ac, color=ACTION_COLORS[ac])
            for bar, v in zip(bars, vals):
                ax.text(bar.get_x() + bar.get_width() / 2, v + 0.6, f"{v:.1f}%", ha="center", fontsize=9)
        ax.annotate(
            "33.3% of High-severity\nattacks are Ignored",
            xy=(2 + w, 36.2),
            xytext=(1.55, 41.5),
            arrowprops=dict(arrowstyle="->", color="#9D174D", lw=1.2),
            fontsize=9,
            color="#9D174D",
            bbox=dict(boxstyle="round,pad=0.3", fc="#FDF2F8", ec="#CC79A7"),
        )
        ax.set_xticks(x)
        ax.set_xticklabels(SEV_ORDER)
        ax.set_ylim(0, 48)
        ax.set_xlabel("Severity Level")
        ax.set_ylabel("Share of Events (%)")
        ax.set_title("Key Finding: Blocking rate (~34%) does not increase for High-severity attacks", loc="left", pad=28)
        _clean_ax(ax, "y")
        ax.legend(frameon=False, ncol=3, loc="lower right", bbox_to_anchor=(1.0, 1.01))
        save_fig(fig, "07_action_by_severity", pdf)

        # 8. Events by Indian state (neutral slate, no collision with DDoS blue)
        state = clean["State"].value_counts().sort_values(ascending=True)
        fig, ax = plt.subplots(figsize=(9.2, 8.6))
        ax.barh(state.index, state.values, color=NEUTRAL_BAR, height=0.7)
        ax.set_xlim(0, state.max() * 1.08)
        ax.set_xlabel("Attack Events (count)")
        ax.set_ylabel("Indian State")
        ax.set_title("Events span 28 Indian states evenly (1,373 to 1,498 events per state)", loc="left", pad=12)
        _clean_ax(ax, "x")
        save_fig(fig, "08_events_by_state", pdf)

        # 9. Box plot: Anomaly score distribution by attack type & severity (legend above, threshold labeled)
        fig, ax = plt.subplots(figsize=(9.6, 5.4))
        positions = []
        data_groups = []
        colors = []
        base_pos = np.arange(len(ATTACK_ORDER)) * 3.5
        for i, at in enumerate(ATTACK_ORDER):
            for j, sv in enumerate(SEV_ORDER):
                positions.append(base_pos[i] + j * 0.85)
                data_groups.append(
                    clean.loc[
                        (clean["Attack Type"] == at) & (clean["Severity Level"] == sv),
                        "Anomaly Scores",
                    ].values
                )
                colors.append(SEV_COLORS[sv])
        bp = ax.boxplot(data_groups, positions=positions, widths=0.65, patch_artist=True, showfliers=False)
        for patch, c in zip(bp["boxes"], colors):
            patch.set_facecolor(c)
            patch.set_edgecolor("#1F2937")
        for med in bp["medians"]:
            med.set_color("#111827")
            med.set_linewidth(1.6)
        ax.axhline(75, linestyle=":", color="#D55E00", linewidth=1.8)
        ax.text(
            positions[-1] + 0.45,
            76.5,
            "High-Anomaly\nThreshold (≥75)",
            color="#D55E00",
            fontsize=8.5,
            fontweight="bold",
            ha="right",
            va="bottom",
            bbox=dict(boxstyle="round,pad=0.2", fc="white", ec="#D55E00", alpha=0.9),
        )
        ax.set_ylim(0, 108)
        ax.set_xticks(base_pos + 0.85)
        ax.set_xticklabels(ATTACK_ORDER)
        ax.set_xlabel("Attack Type")
        ax.set_ylabel("Anomaly Score (0–100 scale)")
        ax.set_title("Anomaly scores average ~50 across all attack types and severity levels", loc="left", pad=28)
        _clean_ax(ax, "y")
        handles = [plt.Rectangle((0, 0), 1, 1, fc=SEV_COLORS[s], ec="#1F2937", label=f"{s} Severity") for s in SEV_ORDER]
        ax.legend(handles=handles, frameon=False, ncol=3, loc="lower right", bbox_to_anchor=(1.0, 1.01))
        save_fig(fig, "09_anomaly_scores_by_type_severity", pdf)

        # 10. Detection flags trigger rate by severity (legend cleanly above)
        fig, ax = plt.subplots(figsize=(10.2, 5.2))
        x = np.arange(len(FLAG_COLS))
        w = 0.25
        for i, sv in enumerate(SEV_ORDER):
            sub = clean[clean["Severity Level"] == sv]
            vals = [(sub[fc] == "Yes").mean() * 100 for fc in FLAG_COLS]
            bars = ax.bar(x + (i - 1) * w, vals, width=w, label=sv, color=SEV_COLORS[sv])
            for bar, v in zip(bars, vals):
                ax.text(bar.get_x() + bar.get_width() / 2, v + 0.7, f"{v:.1f}%", ha="center", fontsize=8.5)
        ax.set_xticks(x)
        ax.set_xticklabels(FLAG_COLS)
        ax.set_ylim(0, 62)
        ax.set_xlabel("Detection Signal")
        ax.set_ylabel("Events with Signal Present (%)")
        ax.set_title("All five detection signals trigger on ~50% of events regardless of severity", loc="left", pad=28)
        _clean_ax(ax, "y")
        ax.legend(frameon=False, ncol=3, loc="lower right", bbox_to_anchor=(1.0, 1.01))
        save_fig(fig, "10_detection_flags_by_severity", pdf)

        # 11. Histogram + KDE of Anomaly Scores (Week 7 Sections II & III: Uniform Distribution)
        scores = clean["Anomaly Scores"].values
        bins = np.arange(0, 105, 5)
        counts, edges = np.histogram(scores, bins=bins)
        centers = 0.5 * (edges[:-1] + edges[1:])
        grid = np.linspace(0, 100, 200)
        bw = 1.06 * scores.std(ddof=1) * (len(scores) ** (-1 / 5))
        kde_density = np.zeros_like(grid)
        for c, cnt in zip(centers, counts):
            kde_density += cnt * np.exp(-0.5 * ((grid - c) / bw) ** 2)
        kde_density = kde_density / (len(scores) * bw * np.sqrt(2 * np.pi))
        kde_scaled = kde_density * len(scores) * 5.0

        fig, ax = plt.subplots(figsize=(10.0, 5.0))
        ax.bar(centers, counts, width=4.5, color=NEUTRAL_BAR, alpha=0.72, edgecolor="white", label="Histogram (bin width = 5)")
        ax.plot(grid, kde_scaled, color=KDE_COLOR, linewidth=2.5, label="Kernel Density Estimate (KDE)")
        ax.axvline(scores.mean(), color="#111827", linestyle="--", linewidth=1.6, label=f"Mean = {scores.mean():.1f}")
        ax.annotate(
            "Flat (Uniform) distribution\n~2,000 events per 5-point bin\nNo outliers outside 0–100",
            xy=(75, counts[15]),
            xytext=(60, counts.max() * 1.12),
            arrowprops=dict(arrowstyle="->", color="#1F2937", lw=1.1),
            fontsize=9,
            bbox=dict(boxstyle="round,pad=0.35", fc="#F8FAFC", ec="#94A3B8"),
        )
        ax.set_xlim(0, 100)
        ax.set_ylim(0, counts.max() * 1.32)
        ax.set_xticks(range(0, 105, 10))
        ax.set_xlabel("Anomaly Score (0–100 scale, bin width = 5)")
        ax.set_ylabel("Frequency (number of events)")
        ax.set_title("Anomaly scores follow a uniform (flat) distribution across 0–100", loc="left", pad=28)
        _clean_ax(ax, "y")
        ax.legend(frameon=False, ncol=3, loc="lower right", bbox_to_anchor=(1.0, 1.01))
        save_fig(fig, "11_anomaly_histogram_kde", pdf)

    print(f"Saved 11 PNGs and {pdf_path.relative_to(BASE)} in {EXPORT_DIR.relative_to(BASE)}/")


def build_interactive_dashboard(clean: pd.DataFrame) -> None:
    """
    Build a standalone interactive HTML dashboard matching Proposal Section 4:
      - Headline KPI row (Total Events, % Blocked, % High Severity, Mean Anomaly Score)
      - Filters for Attack Type, Severity Level, and Year
      - Time-trend charts in the middle (Monthly Trend + Day x Hour Heatmap)
      - Category, Severity, Response, Anomaly, Detection Flags & Geography charts below
    """
    # Compact integer-encoded columnar data for instant exact filtering in browser
    months = sorted(clean["Month"].dt.strftime("%Y-%m").unique().tolist())
    years = sorted(clean["Year"].unique().astype(int).tolist())
    segments = sorted(clean["Network Segment"].unique().tolist())
    protocols = sorted(clean["Protocol"].unique().tolist())
    traffics = sorted(clean["Traffic Type"].unique().tolist())
    states = sorted(clean["State"].unique().tolist())

    m_idx = {m: i for i, m in enumerate(months)}
    y_idx = {y: i for i, y in enumerate(years)}
    d_idx = {d: i for i, d in enumerate(DAY_ORDER)}
    a_idx = {a: i for i, a in enumerate(ATTACK_ORDER)}
    s_idx = {s: i for i, s in enumerate(SEV_ORDER)}
    ac_idx = {a: i for i, a in enumerate(ACTION_ORDER)}
    seg_idx = {s: i for i, s in enumerate(segments)}
    p_idx = {p: i for i, p in enumerate(protocols)}
    t_idx = {t: i for i, t in enumerate(traffics)}
    st_idx = {s: i for i, s in enumerate(states)}

    payload = {
        "meta": {
            "months": months,
            "years": years,
            "days": DAY_ORDER,
            "attacks": ATTACK_ORDER,
            "severities": SEV_ORDER,
            "actions": ACTION_ORDER,
            "segments": segments,
            "protocols": protocols,
            "traffics": traffics,
            "states": states,
            "flags": FLAG_COLS,
            "attackColors": ATTACK_COLORS,
            "sevColors": SEV_COLORS,
            "actionColors": ACTION_COLORS,
        },
        "cols": {
            "m": clean["Month"].dt.strftime("%Y-%m").map(m_idx).tolist(),
            "y": clean["Year"].map(y_idx).tolist(),
            "d": clean["DayOfWeek"].map(d_idx).tolist(),
            "h": clean["Hour"].astype(int).tolist(),
            "a": clean["Attack Type"].map(a_idx).tolist(),
            "s": clean["Severity Level"].astype(str).map(s_idx).tolist(),
            "ac": clean["Action Taken"].map(ac_idx).tolist(),
            "seg": clean["Network Segment"].map(seg_idx).tolist(),
            "p": clean["Protocol"].map(p_idx).tolist(),
            "t": clean["Traffic Type"].map(t_idx).tolist(),
            "st": clean["State"].map(st_idx).tolist(),
            "an": clean["Anomaly Scores"].round(1).tolist(),
            "f": [
                (clean[fc] == "Yes").astype(int).tolist()
                for fc in FLAG_COLS
            ],
        },
    }

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Cyber Security Attack Analysis — Interactive Dashboard</title>
  <script src="https://cdn.plot.ly/plotly-2.35.2.min.js"></script>
  <style>
    :root {{
      --bg: #F8FAFC;
      --card: #FFFFFF;
      --border: #E2E8F0;
      --text: #0F172A;
      --muted: #475569;
      --accent: #0072B2;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Segoe UI", system-ui, -apple-system, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.45;
    }}
    header {{
      background: #0F172A;
      color: #F8FAFC;
      padding: 20px 28px;
      border-bottom: 4px solid var(--accent);
    }}
    header h1 {{ margin: 0 0 4px 0; font-size: 1.45rem; }}
    header p {{ margin: 0; color: #CBD5E1; font-size: 0.92rem; }}
    .container {{ max-width: 1440px; margin: 0 auto; padding: 20px 24px 40px; }}
    .filters {{
      display: flex; flex-wrap: wrap; gap: 14px; align-items: end;
      background: var(--card); border: 1px solid var(--border);
      border-radius: 10px; padding: 14px 18px; margin-bottom: 18px;
    }}
    .filter-group {{ display: flex; flex-direction: column; gap: 4px; min-width: 170px; }}
    .filter-group label {{ font-size: 0.78rem; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; }}
    .filter-group select {{
      padding: 7px 10px; border: 1px solid #CBD5E1; border-radius: 6px;
      font-size: 0.92rem; background: #FFF; color: var(--text);
    }}
    .btn-reset {{
      padding: 8px 16px; border: 1px solid #CBD5E1; border-radius: 6px;
      background: #F1F5F9; color: var(--text); font-weight: 600; cursor: pointer;
    }}
    .btn-reset:hover {{ background: #E2E8F0; }}
    .kpis {{
      display: grid; grid-template-columns: repeat(4, minmax(180px, 1fr));
      gap: 14px; margin-bottom: 20px;
    }}
    .kpi {{
      background: var(--card); border: 1px solid var(--border);
      border-radius: 10px; padding: 16px 18px;
      border-top: 3px solid var(--accent);
    }}
    .kpi-label {{ font-size: 0.8rem; font-weight: 600; color: var(--muted); text-transform: uppercase; }}
    .kpi-value {{ font-size: 1.8rem; font-weight: 700; margin-top: 4px; color: var(--text); }}
    .kpi-sub {{ font-size: 0.8rem; color: var(--muted); margin-top: 2px; }}
    .section-title {{
      font-size: 0.9rem; font-weight: 700; text-transform: uppercase;
      letter-spacing: 0.06em; color: var(--muted); margin: 22px 0 10px;
    }}
    .grid-2 {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; margin-bottom: 16px; }}
    .card {{
      background: var(--card); border: 1px solid var(--border);
      border-radius: 10px; padding: 10px 12px;
    }}
    .chart {{ width: 100%; height: 390px; }}
    .chart-tall {{ width: 100%; height: 640px; }}
    .note {{
      margin-top: 16px; font-size: 0.85rem; color: var(--muted);
      background: #FFFBEB; border: 1px solid #FDE68A; border-radius: 8px; padding: 10px 14px;
    }}
    @media (max-width: 960px) {{
      .kpis {{ grid-template-columns: repeat(2, 1fr); }}
      .grid-2 {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <header>
    <h1>Cyber Security Attack Analysis — Interactive Dashboard</h1>
    <p>Team 04 · Data Visualization · 40,000 Network Security Events (Jan 2020 – Oct 11, 2023) · Okabe-Ito Colorblind-Safe Palette</p>
  </header>

  <div class="container">
    <div class="filters">
      <div class="filter-group">
        <label for="f-attack">Attack Type</label>
        <select id="f-attack"><option value="ALL">All Attack Types</option></select>
      </div>
      <div class="filter-group">
        <label for="f-sev">Severity Level</label>
        <select id="f-sev"><option value="ALL">All Severities</option></select>
      </div>
      <div class="filter-group">
        <label for="f-year">Year</label>
        <select id="f-year"><option value="ALL">All Years (2020–2023)</option></select>
      </div>
      <button class="btn-reset" id="btn-reset">Reset Filters</button>
    </div>

    <div class="kpis">
      <div class="kpi" style="border-top-color:#475569;"><div class="kpi-label">Total Events</div><div class="kpi-value" id="kpi-total">—</div><div class="kpi-sub" id="kpi-total-sub">of 40,000 records</div></div>
      <div class="kpi" style="border-top-color:#2A7B88;"><div class="kpi-label">Percent Blocked</div><div class="kpi-value" id="kpi-blocked">—</div><div class="kpi-sub">Action Taken = Blocked</div></div>
      <div class="kpi" style="border-top-color:#54278F;"><div class="kpi-label">Percent High Severity</div><div class="kpi-value" id="kpi-high">—</div><div class="kpi-sub">Severity Level = High</div></div>
      <div class="kpi" style="border-top-color:#B45309;"><div class="kpi-label">Mean Anomaly Score</div><div class="kpi-value" id="kpi-anom">—</div><div class="kpi-sub">0–100 scale</div></div>
    </div>

    <div class="section-title">1. Time Trends &amp; Peak Activity</div>
    <div class="grid-2">
      <div class="card"><div id="c-monthly" class="chart"></div></div>
      <div class="card"><div id="c-heatmap" class="chart"></div></div>
    </div>

    <div class="section-title">2. Attack Categories, Severity &amp; Network Exposure</div>
    <div class="grid-2">
      <div class="card"><div id="c-type" class="chart"></div></div>
      <div class="card"><div id="c-sev" class="chart"></div></div>
    </div>
    <div class="grid-2">
      <div class="card"><div id="c-tree" class="chart"></div></div>
      <div class="card"><div id="c-bubble" class="chart"></div></div>
    </div>

    <div class="section-title">3. Incident Response, Anomaly Scores &amp; Detection Signals</div>
    <div class="grid-2">
      <div class="card"><div id="c-action" class="chart"></div></div>
      <div class="card"><div id="c-anom" class="chart"></div></div>
    </div>
    <div class="grid-2">
      <div class="card"><div id="c-flags" class="chart"></div></div>
      <div class="card"><div id="c-geo" class="chart-tall"></div></div>
    </div>

    <div class="note">
      <strong>Dataset Note:</strong> Records span Jan 1, 2020 through Oct 11, 2023 (Q4 2023 contains 296 partial-month records). The dataset is synthetic, producing near-uniform category distributions; notably, blocking rates remain ~34% even for High-severity events.
    </div>
  </div>

  <script>
    const DATA = {json.dumps(payload, separators=(",", ":"))};
    const M = DATA.meta;
    const C = DATA.cols;
    const N = C.m.length;

    const selAttack = document.getElementById("f-attack");
    const selSev = document.getElementById("f-sev");
    const selYear = document.getElementById("f-year");

    M.attacks.forEach((v, i) => selAttack.add(new Option(v, i)));
    M.severities.forEach((v, i) => selSev.add(new Option(v, i)));
    M.years.forEach((v, i) => selYear.add(new Option(String(v), i)));

    const BASE_LAYOUT = {{
      template: "plotly_white",
      font: {{ family: "Segoe UI, Arial, sans-serif", size: 12, color: "#1F2937" }},
      margin: {{ l: 58, r: 20, t: 56, b: 48 }},
      legend: {{ orientation: "h", y: 1.02, yanchor: "bottom", x: 1, xanchor: "right" }},
    }};

    function render() {{
      const fa = selAttack.value === "ALL" ? -1 : Number(selAttack.value);
      const fs = selSev.value === "ALL" ? -1 : Number(selSev.value);
      const fy = selYear.value === "ALL" ? -1 : Number(selYear.value);

      let total = 0, blocked = 0, highSev = 0, anomSum = 0;

      const monthly = M.attacks.map(() => new Array(M.months.length).fill(0));
      const heat = M.days.map(() => new Array(24).fill(0));
      const byType = new Array(M.attacks.length).fill(0);
      const sevByType = M.severities.map(() => new Array(M.attacks.length).fill(0));
      const segType = M.segments.map(() => new Array(M.attacks.length).fill(0));
      const protTraf = M.protocols.map(() => new Array(M.traffics.length).fill(0));
      const actBySev = M.severities.map(() => new Array(M.actions.length).fill(0));
      const anomBands = M.severities.map(() => [0, 0, 0, 0]);
      const flagBySev = M.severities.map(() => new Array(M.flags.length).fill(0));
      const sevTotals = new Array(M.severities.length).fill(0);
      const byState = new Array(M.states.length).fill(0);

      for (let i = 0; i < N; i++) {{
        if (fa !== -1 && C.a[i] !== fa) continue;
        if (fs !== -1 && C.s[i] !== fs) continue;
        if (fy !== -1 && C.y[i] !== fy) continue;

        total++;
        const a = C.a[i], s = C.s[i], ac = C.ac[i], an = C.an[i];
        if (ac === 0) blocked++;
        if (s === 2) highSev++;
        anomSum += an;

        monthly[a][C.m[i]]++;
        heat[C.d[i]][C.h[i]]++;
        byType[a]++;
        sevByType[s][a]++;
        segType[C.seg[i]][a]++;
        protTraf[C.p[i]][C.t[i]]++;
        actBySev[s][ac]++;
        sevTotals[s]++;
        const band = an < 25 ? 0 : an < 50 ? 1 : an < 75 ? 2 : 3;
        anomBands[s][band]++;
        for (let k = 0; k < M.flags.length; k++) {{
          flagBySev[s][k] += C.f[k][i];
        }}
        byState[C.st[i]]++;
      }}

      // Update KPIs
      document.getElementById("kpi-total").textContent = total.toLocaleString();
      document.getElementById("kpi-total-sub").textContent = ((total / N) * 100).toFixed(1) + "% of 40,000 records";
      document.getElementById("kpi-blocked").textContent = total ? ((blocked / total) * 100).toFixed(1) + "%" : "0.0%";
      document.getElementById("kpi-high").textContent = total ? ((highSev / total) * 100).toFixed(1) + "%" : "0.0%";
      document.getElementById("kpi-anom").textContent = total ? (anomSum / total).toFixed(1) : "0.0";

      // 1. Monthly trend
      const activeMonthIdx = M.months.map((_, i) => i).filter(i =>
        M.attacks.some((_, a) => monthly[a][i] > 0)
      );
      const xMonths = activeMonthIdx.map(i => M.months[i]);
      const dashStyles = ["solid", "dash", "dot"];
      const monthlyTraces = M.attacks.map((at, a) => ({{
        x: xMonths,
        y: activeMonthIdx.map(i => monthly[a][i]),
        name: at,
        type: "scatter",
        mode: "lines",
        line: {{ color: M.attackColors[at], width: 2.2, dash: dashStyles[a] }},
      }}));
      Plotly.react("c-monthly", monthlyTraces, {{
        ...BASE_LAYOUT,
        title: {{ text: "Monthly Attacks by Type (Oct 2023 is Partial)", x: 0.02 }},
        xaxis: {{ title: "Month" }},
        yaxis: {{ title: "Events (count)", rangemode: "tozero" }},
        shapes: xMonths.includes("2023-10") ? [{{
          type: "rect", x0: "2023-09-20", x1: "2023-10-15", y0: 0, y1: 1, yref: "paper",
          fillcolor: "#E69F00", opacity: 0.2, line: {{ width: 0 }}
        }}] : [],
      }}, {{ responsive: true }});

      // 2. Heatmap
      Plotly.react("c-heatmap", [{{
        z: heat, x: [...Array(24).keys()], y: M.days,
        type: "heatmap", colorscale: "Blues", colorbar: {{ title: "Events" }}
      }}], {{
        ...BASE_LAYOUT,
        title: {{ text: "Attack Counts by Day of Week & Hour", x: 0.02 }},
        xaxis: {{ title: "Hour of Day (0–23)" }},
        yaxis: {{ autorange: "reversed" }},
      }}, {{ responsive: true }});

      // 3. Attack Type horizontal bar
      Plotly.react("c-type", [{{
        y: M.attacks, x: byType, type: "bar", orientation: "h",
        marker: {{ color: M.attacks.map(a => M.attackColors[a]) }},
        text: byType.map(v => v.toLocaleString()), textposition: "auto",
      }}], {{
        ...BASE_LAYOUT,
        showlegend: false,
        title: {{ text: "Attack Counts by Type", x: 0.02 }},
        xaxis: {{ title: "Events (count)" }},
      }}, {{ responsive: true }});

      // 4. Stacked Severity by Attack Type
      const sevTraces = M.severities.map((sv, s) => ({{
        x: M.attacks, y: sevByType[s], name: sv, type: "bar",
        marker: {{ color: M.sevColors[sv] }},
      }}));
      Plotly.react("c-sev", sevTraces, {{
        ...BASE_LAYOUT,
        barmode: "stack",
        title: {{ text: "Severity Distribution by Attack Type", x: 0.02 }},
        yaxis: {{ title: "Events (count)" }},
      }}, {{ responsive: true }});

      // 5. Treemap: Network Segment > Attack Type
      const tLabels = [], tParents = [], tValues = [], tColors = [];
      M.segments.forEach((seg, si) => {{
        const segSum = segType[si].reduce((a, b) => a + b, 0);
        if (segSum === 0) return;
        tLabels.push(seg); tParents.push(""); tValues.push(segSum); tColors.push("#E2E8F0");
        M.attacks.forEach((at, ai) => {{
          if (segType[si][ai] === 0) return;
          tLabels.push(seg + " - " + at);
          tParents.push(seg);
          tValues.push(segType[si][ai]);
          tColors.push(M.attackColors[at]);
        }});
      }});
      Plotly.react("c-tree", [{{
        type: "treemap", labels: tLabels, parents: tParents, values: tValues,
        branchvalues: "total", marker: {{ colors: tColors }},
        textinfo: "label+value+percent parent",
      }}], {{
        ...BASE_LAYOUT,
        margin: {{ l: 12, r: 12, t: 50, b: 12 }},
        title: {{ text: "Attacks by Network Segment & Attack Type", x: 0.02 }},
      }}, {{ responsive: true }});

      // 6. Bubble: Protocol x Traffic Type (high-contrast text)
      const bx = [], by = [], bv = [];
      M.protocols.forEach((p, pi) => {{
        M.traffics.forEach((t, ti) => {{
          bx.push(p); by.push(t); bv.push(protTraf[pi][ti]);
        }});
      }});
      const maxB = Math.max(1, ...bv);
      const minB = Math.min(...bv);
      const midB = (minB + maxB) / 2;
      Plotly.react("c-bubble", [{{
        x: bx, y: by, mode: "markers+text", text: bv.map(v => v.toLocaleString()),
        textfont: {{ color: bv.map(v => v >= midB ? "white" : "#111827"), size: 11 }},
        marker: {{
          size: bv.map(v => Math.max(22, (v / maxB) * 52)),
          color: bv, colorscale: "Blues", cmin: minB * 0.92, cmax: maxB * 1.02, showscale: true,
          line: {{ color: "#1E3A8A", width: 1 }}
        }}
      }}], {{
        ...BASE_LAYOUT,
        showlegend: false,
        title: {{ text: "Attack Counts by Protocol & Traffic Type", x: 0.02 }},
        xaxis: {{ title: "Protocol" }},
        yaxis: {{ title: "Traffic Type" }},
      }}, {{ responsive: true }});

      // 7. Action Taken by Severity (%)
      const actTraces = M.actions.map((ac, ai) => ({{
        x: M.severities,
        y: M.severities.map((_, si) => sevTotals[si] ? Number(((actBySev[si][ai] / sevTotals[si]) * 100).toFixed(1)) : 0),
        name: ac, type: "bar", marker: {{ color: M.actionColors[ac] }},
        textposition: "outside",
      }}));
      actTraces.forEach(tr => tr.text = tr.y.map(v => v + "%"));
      Plotly.react("c-action", actTraces, {{
        ...BASE_LAYOUT,
        barmode: "group",
        title: {{ text: "Key Finding: Response Action Share by Severity (%)", x: 0.02 }},
        yaxis: {{ title: "Share of Events (%)", range: [0, 46], ticksuffix: "%" }},
      }}, {{ responsive: true }});

      // 8. Anomaly Score Bands by Severity
      const bands = ["0-25", "25-50", "50-75", "75-100 (High)"];
      const anomTraces = M.severities.map((sv, s) => ({{
        x: bands, y: anomBands[s], name: sv, type: "bar",
        marker: {{ color: M.sevColors[sv] }},
      }}));
      Plotly.react("c-anom", anomTraces, {{
        ...BASE_LAYOUT,
        barmode: "stack",
        title: {{ text: "Anomaly Score Bands by Severity Level", x: 0.02 }},
        xaxis: {{ title: "Anomaly Score Band (0–100)" }},
        yaxis: {{ title: "Events (count)" }},
      }}, {{ responsive: true }});

      // 9. Detection Flags Trigger Rate by Severity (%)
      const flagTraces = M.severities.map((sv, s) => ({{
        x: M.flags,
        y: M.flags.map((_, k) => sevTotals[s] ? Number(((flagBySev[s][k] / sevTotals[s]) * 100).toFixed(1)) : 0),
        name: sv, type: "bar", marker: {{ color: M.sevColors[sv] }},
      }}));
      Plotly.react("c-flags", flagTraces, {{
        ...BASE_LAYOUT,
        barmode: "group",
        title: {{ text: "Detection Signal Trigger Rate by Severity (%)", x: 0.02 }},
        yaxis: {{ title: "Signal Present (%)", range: [0, 62], ticksuffix: "%" }},
      }}, {{ responsive: true }});

      // 10. Geography: Events by Indian State (neutral slate, no collision with DDoS blue)
      const stPairs = M.states.map((s, i) => [s, byState[i]]).sort((a, b) => a[1] - b[1]);
      Plotly.react("c-geo", [{{
        y: stPairs.map(p => p[0]), x: stPairs.map(p => p[1]),
        type: "bar", orientation: "h", marker: {{ color: "#475569" }},
      }}], {{
        ...BASE_LAYOUT,
        showlegend: false,
        margin: {{ l: 135, r: 20, t: 50, b: 48 }},
        title: {{ text: "Events Across 28 Indian States", x: 0.02 }},
        xaxis: {{ title: "Events (count)" }},
      }}, {{ responsive: true }});
    }}

    selAttack.addEventListener("change", render);
    selSev.addEventListener("change", render);
    selYear.addEventListener("change", render);
    document.getElementById("btn-reset").addEventListener("click", () => {{
      selAttack.value = "ALL";
      selSev.value = "ALL";
      selYear.value = "ALL";
      render();
    }});

    render();
  </script>
</body>
</html>
"""
    DASHBOARD_HTML.write_text(html, encoding="utf-8")
    print(f"Saved interactive dashboard: {DASHBOARD_HTML.relative_to(BASE)}")


def print_summary(clean: pd.DataFrame) -> None:
    act = (
        pd.crosstab(clean["Severity Level"], clean["Action Taken"], normalize="index")
        .mul(100)
        .round(1)
    )
    state = clean["State"].value_counts()
    print("\n--- Numbers to compare with the proposal's Key Findings ---")
    print("Events per year:\n", clean["Year"].value_counts().sort_index())
    print("\nAttack type %:\n", (clean["Attack Type"].value_counts(normalize=True) * 100).round(1))
    print("\nSeverity %:\n", (clean["Severity Level"].value_counts(normalize=True) * 100).round(1))
    print("\nAction taken %:\n", (clean["Action Taken"].value_counts(normalize=True) * 100).round(1))
    print("\nAction % within each severity:\n", act)
    print("\nDevice OS counts:\n", clean["Device OS"].value_counts())
    print("\nBrowser Family counts:\n", clean["Browser Family"].value_counts())
    print("\nMean Anomaly Score:", round(clean["Anomaly Scores"].mean(), 2))
    print(
        "\nStates:", clean["State"].nunique(),
        "| events per state min/max:", state.min(), "/", state.max(),
    )
    print("Q4 2023 rows:", (clean["Quarter"] == "2023Q4").sum())
    print("\nDone. Open dashboard.html or charts/*.html in a browser, and see exports/ for PNG & PDF.")


def main() -> None:
    clean = clean_dataset()
    build_plotly_charts(clean)
    build_static_exports(clean)
    build_interactive_dashboard(clean)
    print_summary(clean)


if __name__ == "__main__":
    main()
