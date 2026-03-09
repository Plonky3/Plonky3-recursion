#!/usr/bin/env python3
"""
Generate a trace-footprint SVG for the last recursive layer of the Fibonacci proof.

Usage:
    python scripts/generate_trace_svg.py [options]

The script runs the recursive_fibonacci example with --emit-trace-json, then renders
an SVG that mirrors trace_shape.svg in layout, style, and colours — only geometry
(widths / heights) is scaled to reflect the actual trace data.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile

# ---------------------------------------------------------------------------
# Colour palette (kept identical to the template SVG)
# ---------------------------------------------------------------------------
MAIN_FILL    = "#b9ddff"
MAIN_STROKE  = "#60a5fa"
PREP_FILL    = "#f8b4d9"
PREP_STROKE  = "#ec4899"
BG_FILL      = "#ffffff"
PANEL_FILL   = "#f8fafc"
PANEL_STROKE = "#cbd5e1"
TEXT_DARK    = "#0f172a"
TEXT_MUTED   = "#475569"
FONT         = "Inter, Arial, sans-serif"

# ---------------------------------------------------------------------------
# Fixed canvas geometry (matches template exactly)
# ---------------------------------------------------------------------------
W, H = 1700, 1000

# ── Area panel (top) ──────────────────────────────────────────────────────
AREA_X, AREA_Y, AREA_W, AREA_H = 40, 120, 1620, 290
AREA_INNER_X = AREA_X + 20          # 60  — where first rect starts
AREA_INNER_W = AREA_W - 40          # 1580 — usable width
AREA_RECT_TOP = AREA_Y + 20         # 140  — top y for rects
AREA_RECT_H   = 250                 # total height for main+prep rects

# Main rect height fraction = 2/3, prep = 1/3 (matches template default).
# We override per-AIR based on actual main/prep ratio.
AREA_RECT_MAIN_H = AREA_RECT_H * 2 / 3   # 166.67
AREA_RECT_PREP_H = AREA_RECT_H / 3       # 83.33

# Minimum visible width for any AIR in the area panel (px)
AREA_MIN_W = 4.0

# ── Per-AIR layout panel (bottom) ────────────────────────────────────────
LAYOUT_X, LAYOUT_Y, LAYOUT_W, LAYOUT_H = 40, 440, 1620, 520

# Bar geometry
BAR_START_X      = 430    # x where column bars start
BAR_AVAIL_W_MAX  = 950    # maximum px budget for bars; label gets the rest
BAR_LABEL_MIN_W  = 240    # minimum px reserved for the "N rows × M cols" label
BAR_H        = 34     # height of each bar row
BAR_Y_FIRST  = 545    # y-top of first bar
BAR_ROW_STEP = 78     # y distance between consecutive bar tops
# Name label sits at the bar midpoint baseline
NAME_LABEL_DY = BAR_H // 2 + 6   # ≈ 23 px below bar top → baseline at bar y + 23


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def fmt_int(n: int) -> str:
    return f"{n:,}"


def rect_el(x, y, w, h, rx=0, fill=BG_FILL, stroke="none", sw=0):
    return (
        f'<rect x="{x:.2f}" y="{y:.2f}" width="{w:.2f}" height="{h:.2f}" '
        f'rx="{rx}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"/>'
    )


def text_el(x, y, content, size=14, weight=400, fill=TEXT_MUTED, anchor="start"):
    return (
        f'<text x="{x}" y="{y}" font-family="{FONT}" font-size="{size}" '
        f'font-weight="{weight}" fill="{fill}" text-anchor="{anchor}">'
        f"{content}</text>"
    )


# ---------------------------------------------------------------------------
# Derived statistics
# ---------------------------------------------------------------------------

def enrich(airs: list[dict]) -> list[dict]:
    for a in airs:
        a["total_cols"]  = a["main_cols"] + a["prep_cols"]
        a["main_cells"]  = a["main_cols"] * a["rows"]
        a["prep_cells"]  = a["prep_cols"] * a["rows"]
        a["total_cells"] = a["total_cols"] * a["rows"]
    return airs


# ---------------------------------------------------------------------------
# Area panel
# ---------------------------------------------------------------------------

def build_area_panel(airs: list[dict], total_cells: int) -> list[str]:
    """Horizontal strip: width ∝ total_cells, height split by main/prep ratio."""
    lines: list[str] = []
    lines.append(rect_el(AREA_X, AREA_Y, AREA_W, AREA_H, rx=14,
                         fill=PANEL_FILL, stroke=PANEL_STROKE, sw=1.2))

    # Compute raw widths proportional to total_cells; then enforce min visible width
    raw_widths = [AREA_INNER_W * a["total_cells"] / total_cells for a in airs]

    # Clamp very small slices to AREA_MIN_W, scaling others down proportionally
    # so the total still equals AREA_INNER_W.
    clamped = [max(AREA_MIN_W, w) for w in raw_widths]
    overflow = sum(clamped) - AREA_INNER_W
    if overflow > 0:
        # Reduce the largest slices proportionally
        large_total = sum(w for w in clamped if w > AREA_MIN_W)
        if large_total > 0:
            clamped = [
                w if w <= AREA_MIN_W else w - overflow * (w / large_total)
                for w in clamped
            ]

    cursor_x = float(AREA_INNER_X)

    for i, air in enumerate(airs):
        w = clamped[i]
        # Height split: main ∝ main_cells, prep ∝ prep_cells within AREA_RECT_H
        tc = air["total_cells"]
        frac_main = air["main_cells"] / tc if tc else 2 / 3
        h_main = AREA_RECT_H * frac_main
        h_prep = AREA_RECT_H - h_main

        main_y = float(AREA_RECT_TOP)
        prep_y = main_y + h_main

        lines.append(rect_el(cursor_x, main_y, w, h_main, rx=10,
                              fill=MAIN_FILL, stroke=MAIN_STROKE, sw=1.2))
        lines.append(rect_el(cursor_x, prep_y, w, h_prep, rx=10,
                              fill=PREP_FILL, stroke=PREP_STROKE, sw=1.2))

        # Info text — only if the slice is wide enough
        tx = cursor_x + 10
        text_block_bottom = main_y   # tracks the y-bottom of the last info text line
        if w >= 60:
            # Choose font size based on available width
            fs_title = 20 if w >= 400 else (15 if w >= 180 else 12)
            fs_body  = 14 if w >= 400 else (13 if w >= 180 else 10)
            ty = main_y + 24
            lines.append(text_el(tx, ty,        air["name"],                         fs_title, 700, TEXT_DARK))
            lines.append(text_el(tx, ty + fs_title + 4,  f"Total: {fmt_int(tc)} cells",       fs_body,  400, TEXT_MUTED))
            lines.append(text_el(tx, ty + fs_title + 4 + (fs_body + 4),   f"Rows: {fmt_int(air['rows'])}",           fs_body,  400, TEXT_MUTED))
            lines.append(text_el(tx, ty + fs_title + 4 + 2*(fs_body + 4), f"Main cols: {air['main_cols']}",           fs_body,  400, TEXT_MUTED))
            lines.append(text_el(tx, ty + fs_title + 4 + 3*(fs_body + 4), f"Prep cols: {air['prep_cols']}",           fs_body,  400, TEXT_MUTED))
            # bottom of the last text line (baseline + a little descender room)
            text_block_bottom = ty + fs_title + 4 + 3*(fs_body + 4) + 6

        # Centre "main N" / "prep N" labels — only when there is vertical room.
        # Push the label below the info text block; skip if it would overlap prep rect.
        cx = cursor_x + w / 2
        if w >= 80:
            centre_label_size = 15
            # Ideal position: geometric centre of the main rect
            ideal_y = main_y + h_main / 2 + 5
            # If the text block reaches past the ideal position, shift label down
            label_y = max(ideal_y, text_block_bottom + centre_label_size)
            # Only emit if the label fits inside the main rect (with 4px margin)
            if label_y <= prep_y - 4:
                lines.append(text_el(cx, label_y,
                                      f"main {fmt_int(air['main_cells'])}", centre_label_size, 700, TEXT_DARK, "middle"))
            lines.append(text_el(cx, prep_y + h_prep / 2 + 5,
                                  f"prep {fmt_int(air['prep_cells'])}", 14, 700, TEXT_DARK, "middle"))

        cursor_x += w

    return lines


# ---------------------------------------------------------------------------
# Per-AIR layout sketch panel
# ---------------------------------------------------------------------------

def build_layout_panel(airs: list[dict]) -> list[str]:
    """Horizontal bar per AIR: width ∝ column count; right marker ∝ row count."""
    lines: list[str] = []
    lines.append(rect_el(LAYOUT_X, LAYOUT_Y, LAYOUT_W, LAYOUT_H, rx=14,
                          fill=PANEL_FILL, stroke=PANEL_STROKE, sw=1.2))
    lines.append(text_el(58, LAYOUT_Y + 32, "Per-AIR layout sketch", 18, 700, TEXT_DARK))
    lines.append(text_el(
        58, LAYOUT_Y + 54,
        "Each bar shows main columns followed by preprocessed columns. "
        "The gray marker on the right indicates relative row count.",
        14, 400, TEXT_MUTED,
    ))

    max_cols = max(a["total_cols"] for a in airs)
    # Reserve enough room for the label to the right of the widest bar.
    bar_avail_w = min(BAR_AVAIL_W_MAX, W - BAR_START_X - BAR_LABEL_MIN_W)
    px_per_col = bar_avail_w / max_cols if max_cols else 1

    for idx, air in enumerate(airs):
        bar_y = BAR_Y_FIRST + idx * BAR_ROW_STEP

        # AIR name label (left column, at bar vertical centre)
        lines.append(text_el(64, bar_y + BAR_H // 2 + 6, air["name"], 16, 700, TEXT_DARK))

        w_main = air["main_cols"] * px_per_col
        w_prep = air["prep_cols"] * px_per_col

        # Main trace bar
        lines.append(rect_el(BAR_START_X, bar_y, w_main, BAR_H, rx=8,
                              fill=MAIN_FILL, stroke=MAIN_STROKE, sw=1.2))
        # Prep trace bar (immediately right of main)
        if w_prep > 0:
            lines.append(rect_el(BAR_START_X + w_main, bar_y, w_prep, BAR_H, rx=8,
                                  fill=PREP_FILL, stroke=PREP_STROKE, sw=1.2))

        # Column labels inside / above bars
        total_bar_w = w_main + w_prep
        if air["total_cols"] <= 12:
            label_above_y = bar_y - 2
            lines.append(text_el(
                BAR_START_X + w_main / 2, label_above_y,
                str(air["main_cols"]), 13, 700, TEXT_DARK, "middle",
            ))
            if air["prep_cols"] > 0:
                lines.append(text_el(
                    BAR_START_X + w_main + w_prep / 2, label_above_y,
                    str(air["prep_cols"]), 13, 700, TEXT_DARK, "middle",
                ))
        else:
            main_cx = BAR_START_X + w_main / 2
            prep_cx = BAR_START_X + w_main + w_prep / 2
            if w_main >= 60:
                lines.append(text_el(main_cx, bar_y + BAR_H - 11,
                                      f"{air['main_cols']} main cols", 13, 700, TEXT_DARK, "middle"))
            if w_prep >= 60:
                lines.append(text_el(prep_cx, bar_y + BAR_H - 11,
                                      f"{air['prep_cols']} prep cols", 13, 700, TEXT_DARK, "middle"))

        # "N rows × M total cols" label — right of bars
        end_x = BAR_START_X + total_bar_w + 14
        label_str = f"{fmt_int(air['rows'])} rows \u00d7 {air['total_cols']} total cols"
        lines.append(text_el(end_x, bar_y + BAR_H // 2 + 5, label_str, 14, 400, TEXT_MUTED))

    return lines


# ---------------------------------------------------------------------------
# Full SVG assembly
# ---------------------------------------------------------------------------

def build_svg(airs: list[dict], layer: int, n: int | None, example: str = "recursive_fibonacci") -> str:
    airs = enrich(airs)

    total_cells = sum(a["total_cells"] for a in airs)
    total_main  = sum(a["main_cells"]  for a in airs)
    total_prep  = sum(a["prep_cells"]  for a in airs)
    pct_main = total_main / total_cells * 100 if total_cells else 0
    pct_prep = total_prep / total_cells * 100 if total_cells else 0

    lines: list[str] = []

    # Canvas background
    lines.append(rect_el(0, 0, W, H, fill=BG_FILL))

    # ── Header ──────────────────────────────────────────────────────────
    lines.append(text_el(40, 48, "Batch STARK trace footprint", 30, 700, TEXT_DARK))
    lines.append(text_el(
        40, 76,
        f"Area is proportional to total cells. Blue = main trace, pink = preprocessed trace. "
        f"Total cells = {fmt_int(total_cells)}",
        15, 400, TEXT_MUTED,
    ))
    # Legend
    lines.append(rect_el(40, 84, 18, 18, rx=4, fill=MAIN_FILL, stroke=MAIN_STROKE, sw=1.2))
    lines.append(text_el(68, 98.5, f"Main trace ({fmt_int(total_main)} cells, {pct_main:.1f}%)", 15))
    lines.append(rect_el(395, 84, 18, 18, rx=4, fill=PREP_FILL, stroke=PREP_STROKE, sw=1.2))
    lines.append(text_el(423, 98.5, f"Preprocessed trace ({fmt_int(total_prep)} cells, {pct_prep:.1f}%)", 15))

    # ── Area panel ──────────────────────────────────────────────────────
    lines += build_area_panel(airs, total_cells)

    # ── Layout panel ────────────────────────────────────────────────────
    lines += build_layout_panel(airs)

    # ── Footer ──────────────────────────────────────────────────────────
    n_suffix = f" (N = {fmt_int(n)})" if n is not None else ""
    lines.append(text_el(
        W - 40, H - 18,
        f"Last recursive layer (layer {layer}) — {example}{n_suffix}.",
        12, 400, TEXT_MUTED, "end",
    ))

    header = f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">\n'
    body   = "\n".join(lines)
    return header + body + "\n</svg>\n"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Run a recursion example and generate a trace-footprint SVG.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--example", default="recursive_fibonacci",
                   help="Name of the cargo example to run (must support --emit-trace-json)")
    p.add_argument("--field", default="koala-bear",
                   choices=["koala-bear", "baby-bear", "goldilocks"])
    p.add_argument("-n", "--n", type=int, default=None,
                   help="Fibonacci index F(n) — only used for recursive_fibonacci (default: 10000)")
    p.add_argument("--num-recursive-layers", type=int, default=3)
    p.add_argument("--log-blowup",          type=int, default=2)
    p.add_argument("--max-log-arity",       type=int, default=3)
    p.add_argument("--log-final-poly-len",  type=int, default=5)
    p.add_argument("--query-pow-bits",      type=int, default=18)
    p.add_argument("--output", "-o", default="trace_shape.svg",
                   help="Path to write the generated SVG")
    p.add_argument("--json-output", default=None,
                   help="Also save the raw JSON to this path (optional)")
    p.add_argument("--skip-run", default=None, metavar="JSON_PATH",
                   help="Skip running cargo; load trace shapes from this JSON file instead")
    p.add_argument("--release", action="store_true", default=True)
    p.add_argument("-q", "--quiet", action="store_true", default=True)
    p.add_argument("--no-release", dest="release", action="store_false")
    return p


def main() -> int:
    args = build_arg_parser().parse_args()

    if args.skip_run:
        print(f"Loading trace shapes from {args.skip_run} …")
        with open(args.skip_run) as f:
            data = json.load(f)
    else:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            json_path = tf.name

        try:
            workspace = os.path.join(os.path.dirname(__file__), "..")
            cmd = [
                "cargo", "run",
                *( ["--release"] if args.release else [] ),
                "--example", args.example,
                "--manifest-path", os.path.join(workspace, "Cargo.toml"),
                "--",
                "--field",               args.field,
                *( ["--n", str(args.n if args.n is not None else 10000)]
                   if args.example != "recursive_aggregation" else [] ),
                "--num-recursive-layers", str(args.num_recursive_layers),
                "--log-blowup",          str(args.log_blowup),
                "--max-log-arity",       str(args.max_log_arity),
                "--log-final-poly-len",  str(args.log_final_poly_len),
                "--query-pow-bits",      str(args.query_pow_bits),
                "--emit-trace-json",     json_path,
            ]
            print("Running:", " ".join(cmd))
            env = os.environ.copy()
            env.setdefault("RUST_LOG", "warn")
            result = subprocess.run(cmd, check=False, env=env)
            if result.returncode != 0:
                print(f"cargo run failed (exit {result.returncode})", file=sys.stderr)
                return 1

            with open(json_path) as f:
                data = json.load(f)
        finally:
            try:
                os.unlink(json_path)
            except OSError:
                pass

    if args.json_output:
        with open(args.json_output, "w") as f:
            json.dump(data, f, indent=2)
        print(f"JSON saved to {args.json_output}")

    airs  = data["airs"]
    layer = data.get("layer", 1)
    n_val = data.get("n") or args.n  # None for examples that don't emit n

    if not airs:
        print("No AIR data found in JSON.", file=sys.stderr)
        return 1

    svg = build_svg(airs, layer, n_val, example=args.example)
    with open(args.output, "w") as f:
        f.write(svg)
    print(f"SVG written to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
