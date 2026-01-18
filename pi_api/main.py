#!/usr/bin/env python3

import cv2
import threading
import time
import base64
from flask import Flask, jsonify

# -----------------------------
# Configuration
# -----------------------------
WIDTH = 640
HEIGHT = 480
FPS = 30

# -----------------------------
# Global state
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

    # Open the default Raspberry Pi camera (V4L2)
    cap = cv2.VideoCapture(0)
    cap.set(cv2.CAP_PROP_FRAME_WIDTH, WIDTH)
    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, HEIGHT)
    cap.set(cv2.CAP_PROP_FPS, FPS)

    if not cap.isOpened():
        with camera_lock:
            camera_running = False
        print("⚠️ Could not open camera")
        return

    while True:
        with camera_lock:
            if stop_camera:
                break

        ret, frame = cap.read()
        if not ret:
            continue

        with frame_lock:
            latest_frame = frame.copy()

        time.sleep(0.01)

    cap.release()
    with camera_lock:
        camera_running = False
        stop_camera = False

# -----------------------------
# Camera control
# -----------------------------
def start_camera():
    global camera_thread, camera_running, stop_camera
    with camera_lock:
        if camera_running:
            return
        stop_camera = False
        camera_running = True
        camera_thread = threading.Thread(target=camera_loop, daemon=True)
        camera_thread.start()

def shutdown_camera():
    global stop_camera
    with camera_lock:
        stop_camera = True

# -----------------------------
# Flask API
# -----------------------------
app = Flask(__name__)

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

    # Convert frame to JPEG bytes
    ret, buffer = cv2.imencode(".jpg", frame)
    if not ret:
        return jsonify({"error": "Failed to encode frame"}), 500

    # Encode JPEG to base64
    image_base64 = base64.b64encode(buffer.tobytes()).decode("utf-8")

    # Stop camera after capture
    shutdown_camera()

    return jsonify({
        "status": "ok",
        "image_base64": image_base64
    })

# -----------------------------
# Health check
# -----------------------------
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200

# -----------------------------
# Main
# -----------------------------
if __name__ == "__main__":
    print("🟢 Pi Capture API running")
    app.run(host="0.0.0.0", port=8080, threaded=True)
