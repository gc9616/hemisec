#!/usr/bin/env python3

import cv2
import threading
import time
from flask import Flask, Response, jsonify

# -----------------------------
# Configuration
# -----------------------------
WIDTH = 640
HEIGHT = 480
FPS = 30

GSTREAMER_PIPELINE = (
    f"libcamerasrc ! "
    f"video/x-raw,width={WIDTH},height={HEIGHT},framerate={FPS}/1 ! "
    f"videoconvert ! appsink"
)

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
# Camera loop (single owner)
# -----------------------------
def camera_loop():
    global latest_frame, camera_running, stop_camera

    cap = cv2.VideoCapture(GSTREAMER_PIPELINE, cv2.CAP_GSTREAMER)
    if not cap.isOpened():
        with camera_lock:
            camera_running = False
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

        time.sleep(0.005)

    cap.release()
    with camera_lock:
        camera_running = False
        stop_camera = False

# -----------------------------
# Camera lifecycle helpers
# -----------------------------
def start_camera():
    global camera_thread, camera_running, stop_camera

    with camera_lock:
        if camera_running:
            return
        stop_camera = False
        camera_running = True

        camera_thread = threading.Thread(
            target=camera_loop,
            daemon=True
        )
        camera_thread.start()

def shutdown_camera():
    global stop_camera

    with camera_lock:
        stop_camera = True

# -----------------------------
# Flask app
# -----------------------------
app = Flask(__name__)

def mjpeg_generator():
    start_camera()

    try:
        while True:
            with frame_lock:
                if latest_frame is None:
                    continue
                frame = latest_frame.copy()

            ret, buffer = cv2.imencode(".jpg", frame)
            if not ret:
                continue

            yield (
                b"--frame\r\n"
                b"Content-Type: image/jpeg\r\n\r\n" +
                buffer.tobytes() +
                b"\r\n"
            )
    finally:
        # Client disconnected
        shutdown_camera()

@app.route("/video")
def video():
    return Response(
        mjpeg_generator(),
        mimetype="multipart/x-mixed-replace; boundary=frame"
    )

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

    filename = f"/tmp/capture_{int(time.time())}.jpg"
    cv2.imwrite(filename, frame)

    # Shut down camera immediately after capture
    shutdown_camera()

    return jsonify({
        "status": "ok",
        "file": filename
    })

# -----------------------------
# Main
# -----------------------------
if __name__ == "__main__":
    print("🟢 API running (camera OFF)")
    print("▶ Camera starts on /video")
    print("📸 Camera stops immediately after /capture")

    app.run(host="0.0.0.0", port=8443, threaded=True)