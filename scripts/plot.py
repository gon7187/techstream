"""Small SVG chart for decoded sample indices; no plotting dependency or I/O."""

import html
import math


def sample_chart(
    samples: list[dict], pid: str, *, width: int = 1024, height: int = 300
) -> str:
    if (
        not 1 <= len(samples) <= 10000
        or not 320 <= width <= 4096
        or not 180 <= height <= 2160
    ):
        raise ValueError("Chart bounds or sample count are invalid")
    values = []
    unit = ""
    for sample in samples:
        matches = [v for v in sample["values"] if v["pid"] == pid]
        if len(matches) != 1:
            raise ValueError("Chart requires one matching PID in every sample")
        value = matches[0]["value"]
        if type(value) not in (int, float) or not math.isfinite(value):
            raise ValueError("Chart values must be finite numbers")
        values.append(value)
        current_unit = matches[0]["unit"]
        if len(values) > 1 and current_unit != unit:
            raise ValueError("Chart units change between samples")
        unit = current_unit
    low, high = min(values), max(values)
    if low == high:
        low, high = low - 0.5, high + 0.5
    left, top, right, bottom = 78, 35, width - 25, height - 52
    points = [
        (
            left + index * (right - left) / max(1, len(values) - 1),
            bottom - (value - low) * (bottom - top) / (high - low),
        )
        for index, value in enumerate(values)
    ]
    line = " ".join(f"{x:.2f},{y:.2f}" for x, y in points)
    labels = []
    for step in range(5):
        y = top + step * (bottom - top) / 4
        value = high - step * (high - low) / 4
        labels.append(
            f'<path d="M{left} {y}H{right}" stroke="#34495b"/><text x="{left - 10}" y="{y + 5}" text-anchor="end">{value:.2f}</text>'
        )
    markers = "".join(
        f'<circle cx="{x:.2f}" cy="{y:.2f}" r="3" fill="#65baff"/>' for x, y in points
    )
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
<rect width="100%" height="100%" rx="10" fill="#192635"/>
<g fill="#d1dbe6" font-family="sans-serif" font-size="14">{"".join(labels)}
<text x="{left}" y="22">{html.escape(unit)}</text>
<text x="{left}" y="{height - 22}">1</text><text x="{right}" y="{height - 22}" text-anchor="end">{len(values)}</text>
<text x="{width / 2}" y="{height - 8}" text-anchor="middle">Номер отсчёта</text></g>
<polyline points="{line}" fill="none" stroke="#65baff" stroke-width="2.5"/>{markers}</svg>'''
