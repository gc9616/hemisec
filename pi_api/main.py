#!/usr/bin/env python3

import cv2
import threading
import time
import base64
from flask import Flask, Response, jsonify, request

# -----------------------------
# Configuration
# -----------------------------
WIDTH = 640
HEIGHT = 480
FPS = 30

# -----------------------------
# Global camera state
# -----------------------------
latest_frame = None
frame_lock = threading.Lock()

camera_thread = None
camera_running = False
stop_camera = False
camera_lock = threading.Lock()

# -----------------------------
# Camera loop
# -----------------------------
def camera_loop():
    global latest_frame, camera_running, stop_camera

    # Use V4L2 device (raspicam stack)
    cap = cv2.VideoCapture(0)
    cap.set(cv2.CAP_PROP_FRAME_WIDTH, WIDTH)
    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, HEIGHT)
    cap.set(cv2.CAP_PROP_FPS, FPS)

    if not cap.isOpened():
        with camera_lock:
            camera_running = False
        print("❌ Camera failed to open")
        return

    print("▶ Camera started")
    while True:
        with camera_lock:
            if stop_camera:
                break

        ret, frame = cap.read()
        if not ret:
            continue

        with frame_lock:
            latest_frame = frame.copy()

        time.sleep(1 / FPS)

    cap.release()
    with camera_lock:
        camera_running = False
        stop_camera = False
    print("⏹ Camera stopped")

# -----------------------------
# Camera control
# -----------------------------
def start_camera():
    global camera_thread, camera_running
    with camera_lock:
        if camera_running:
            return
        camera_thread = threading.Thread(target=camera_loop, daemon=True)
        camera_thread.start()
        camera_running = True

def shutdown_camera():
    global stop_camera
    with camera_lock:
        stop_camera = True

# -----------------------------
# Flask API
# -----------------------------
app = Flask(__name__)

@app.route("/")
def root():
    return jsonify({
        "message": "PalmVein Biometric Device API",
        "version": "1.0.0",
        "endpoints": {
            "video_frame": "GET /video_frame -> Returns single JPEG frame for polling",
            "capture": "POST /capture -> Returns base64 image for backend",
        }
    })

# -----------------------------
# Polling-friendly single frame endpoint
# -----------------------------
@app.route("/video_frame")
def video_frame():
    start_camera()

    # Wait briefly for first frame
    timeout = time.time() + 2
    while latest_frame is None and time.time() < timeout:
        time.sleep(0.05)

    with frame_lock:
        if latest_frame is None:
            return jsonify({"error": "No frame available"}), 503
        frame = latest_frame.copy()

    ret, buffer = cv2.imencode(".jpg", frame)
    if not ret:
        return jsonify({"error": "Could not encode frame"}), 500

    return Response(buffer.tobytes(), mimetype="image/jpeg")

# -----------------------------
# Capture endpoint (returns base64)
# -----------------------------
@app.route("/capture", methods=["POST"])
def capture():
    start_camera()

    # Wait briefly for a frame
    timeout = time.time() + 2
    while latest_frame is None and time.time() < timeout:
        time.sleep(0.05)

    with frame_lock:
        if latest_frame is None:
            return jsonify({"error": "No frame available"}), 503
        frame = latest_frame.copy()

    # Encode to JPEG
    ret, buffer = cv2.imencode(".jpg", frame)
    if not ret:
        return jsonify({"error": "Could not encode frame"}), 500

    # Encode JPEG to base64
    image_base64 = base64.b64encode(buffer).decode("utf-8")

    # Optionally shut down camera after capture
    # Commented out if you want continuous polling
    # shutdown_camera()

    return jsonify({
        "status": "ok",
        "image_base64": image_base64
    })

# -----------------------------
# Health check
# -----------------------------
@app.route("/health")
def health():
    return jsonify({"status": "ok", "camera_running": camera_running})

# -----------------------------
# Main
# -----------------------------
if __name__ == "__main__":
    print("🟢 PalmVein Pi API running")
    print("▶ Camera will start on /video_frame or /capture")
    app.run(host="0.0.0.0", port=8080, threaded=True)
