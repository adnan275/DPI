import io
import os
import sys
import json
import uuid
import threading
import tempfile
from flask import Flask, request, jsonify, send_file, render_template

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dpi.dpi_engine import DPIEngine, DPIConfig
from dpi.types import AppType, app_type_to_string

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024

UPLOAD_FOLDER = tempfile.gettempdir()
results_store = {}
results_lock = threading.Lock()

SUPPORTED_APPS = [
    "Google", "YouTube", "Facebook", "Instagram", "Twitter/X",
    "Netflix", "Amazon", "Microsoft", "Apple", "WhatsApp",
    "Telegram", "TikTok", "Spotify", "Zoom", "Discord", "GitHub"
]


def run_dpi_analysis(job_id, input_path, output_path, block_ips, block_apps, block_domains, lbs, fps):
    captured_output = []
    original_print = __builtins__["print"] if isinstance(__builtins__, dict) else print

    import builtins
    original_print = builtins.print

    def capture_print(*args, **kwargs):
        line = " ".join(str(a) for a in args)
        captured_output.append(line)

    builtins.print = capture_print

    try:
        config = DPIConfig(num_load_balancers=lbs, fps_per_lb=fps)
        engine = DPIEngine(config)

        if not engine.initialize():
            with results_lock:
                results_store[job_id] = {"status": "error", "message": "Engine init failed"}
            return

        for ip in block_ips:
            engine.block_ip(ip.strip())

        for a in block_apps:
            engine.block_app(a.strip())

        for d in block_domains:
            engine.block_domain(d.strip())

        success = engine.process_file(input_path, output_path)

        if not success:
            with results_lock:
                results_store[job_id] = {"status": "error", "message": "Processing failed"}
            return

        stats = engine.get_stats()
        fp_stats = engine._fp_manager.get_aggregated_stats() if engine._fp_manager else {}
        lb_stats = engine._lb_manager.get_aggregated_stats() if engine._lb_manager else {}
        rule_stats = engine._rule_manager.get_stats() if engine._rule_manager else {}

        app_breakdown = {}
        if engine._fp_manager:
            raw = engine._fp_manager.generate_classification_report()
            for line in raw.split("\n"):
                if ":" in line and "%" in line:
                    parts = line.strip().split(":")
                    if len(parts) == 2:
                        app_name = parts[0].strip().lstrip("║").strip()
                        count_part = parts[1].strip()
                        try:
                            count = int(count_part.split()[0])
                            if count > 0:
                                app_breakdown[app_name] = count
                        except Exception:
                            pass

        drop_rate = 0.0
        if stats.total_packets > 0:
            drop_rate = round(100.0 * stats.dropped_packets / stats.total_packets, 2)

        output_size = 0
        try:
            output_size = os.path.getsize(output_path)
        except Exception:
            pass

        result = {
            "status": "done",
            "stats": {
                "total_packets": stats.total_packets,
                "total_bytes": stats.total_bytes,
                "tcp_packets": stats.tcp_packets,
                "udp_packets": stats.udp_packets,
                "forwarded_packets": stats.forwarded_packets,
                "dropped_packets": stats.dropped_packets,
                "drop_rate": drop_rate,
                "active_connections": fp_stats.get("total_connections", 0),
                "lb_received": lb_stats.get("total_received", 0),
                "lb_dispatched": lb_stats.get("total_dispatched", 0),
                "fp_processed": fp_stats.get("total_processed", 0),
                "fp_forwarded": fp_stats.get("total_forwarded", 0),
                "fp_dropped": fp_stats.get("total_dropped", 0),
                "blocked_ips": rule_stats.get("blocked_ips", 0),
                "blocked_apps": rule_stats.get("blocked_apps", 0),
                "blocked_domains": rule_stats.get("blocked_domains", 0),
                "output_size_bytes": output_size,
            },
            "app_breakdown": app_breakdown,
            "log": captured_output[-30:],
            "output_path": output_path,
        }

        with results_lock:
            results_store[job_id] = result

    except Exception as e:
        with results_lock:
            results_store[job_id] = {"status": "error", "message": str(e)}
    finally:
        builtins.print = original_print


@app.route("/")
def index():
    return render_template("index.html", supported_apps=SUPPORTED_APPS)


@app.route("/analyze", methods=["POST"])
def analyze():
    if "pcap" not in request.files:
        return jsonify({"error": "No PCAP file uploaded"}), 400

    pcap_file = request.files["pcap"]
    if not pcap_file.filename:
        return jsonify({"error": "Empty filename"}), 400

    block_ips = [x for x in request.form.get("block_ips", "").split(",") if x.strip()]
    block_apps = [x for x in request.form.get("block_apps", "").split(",") if x.strip()]
    block_domains = [x for x in request.form.get("block_domains", "").split(",") if x.strip()]
    lbs = int(request.form.get("lbs", 2))
    fps = int(request.form.get("fps", 2))

    job_id = str(uuid.uuid4())

    input_path = os.path.join(UPLOAD_FOLDER, f"input_{job_id}.pcap")
    output_path = os.path.join(UPLOAD_FOLDER, f"output_{job_id}.pcap")

    pcap_file.save(input_path)

    with results_lock:
        results_store[job_id] = {"status": "processing"}

    t = threading.Thread(
        target=run_dpi_analysis,
        args=(job_id, input_path, output_path, block_ips, block_apps, block_domains, lbs, fps),
        daemon=True
    )
    t.start()

    return jsonify({"job_id": job_id})


@app.route("/result/<job_id>")
def get_result(job_id):
    with results_lock:
        result = results_store.get(job_id)
    if result is None:
        return jsonify({"status": "not_found"}), 404
    return jsonify(result)


@app.route("/download/<job_id>")
def download(job_id):
    with results_lock:
        result = results_store.get(job_id)

    if not result or result.get("status") != "done":
        return jsonify({"error": "Not ready"}), 400

    output_path = result.get("output_path")
    if not output_path or not os.path.exists(output_path):
        return jsonify({"error": "Output file not found"}), 404

    return send_file(
        output_path,
        as_attachment=True,
        download_name="filtered_output.pcap",
        mimetype="application/vnd.tcpdump.pcap"
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
