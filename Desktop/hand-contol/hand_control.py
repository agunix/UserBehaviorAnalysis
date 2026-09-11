import os
import cv2
import mediapipe as mp
import urllib.request
from mediapipe.tasks import python as mp_python
from mediapipe.tasks.python import vision
import pyautogui
import numpy as np
import time
import math

# configuraiton

CAM_INDEX = 0
FRAME_W, FRAME_H = 640, 480          
FRAME_MARGIN = 100                    
SMOOTHING = 5                         
CLICK_DISTANCE = 35                   
CLICK_COOLDOWN = 0.4                  
SCROLL_SENSITIVITY = 4                

pyautogui.FAILSAFE = False

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hand_landmarker.task")
MODEL_URL = "https://storage.googleapis.com/mediapipe-models/hand_landmarker/hand_landmarker/float16/1/hand_landmarker.task"

# # Standard connections of 21 points (finger-to-finger lines) for drawing the hand skeleton
HAND_CONNECTIONS = list(vision.HandLandmarksConnections.HAND_CONNECTIONS)


# MediaPipe HandLandmarker setup (new Tasks API, instead of "solutions")
def ensure_model():
    """hand_landmarker.task model faylı yoxdursa, avtomatik endirir."""
    if not os.path.exists(MODEL_PATH):
        print("Model endirilir (hand_landmarker.task)...")
        urllib.request.urlretrieve(MODEL_URL, MODEL_PATH)
        print("Model endirildi:", MODEL_PATH)


ensure_model()

base_options = mp_python.BaseOptions(model_asset_path=MODEL_PATH)
options = vision.HandLandmarkerOptions(
    base_options=base_options,
    num_hands=1,
    min_hand_detection_confidence=0.7,
    min_tracking_confidence=0.7,
    running_mode=vision.RunningMode.VIDEO,
)
landmarker = vision.HandLandmarker.create_from_options(options)

SCREEN_W, SCREEN_H = pyautogui.size()

# Fingertip (tip) and knuckle (pip) landmark indices
TIP_IDS = {"thumb": 4, "index": 8, "middle": 12, "ring": 16, "pinky": 20}
PIP_IDS = {"thumb": 2, "index": 6, "middle": 10, "ring": 14, "pinky": 18}


def fingers_up(landmarks, handedness_label):
    """Returns (1/0) whether each finger is up or down."""
    fingers = {}

    # Thumb: comparison along the x-axis (direction changes depending on right/left hand)
    if handedness_label == "Right":
        fingers["thumb"] = 1 if landmarks[TIP_IDS["thumb"]].x < landmarks[PIP_IDS["thumb"]].x else 0
    else:
        fingers["thumb"] = 1 if landmarks[TIP_IDS["thumb"]].x > landmarks[PIP_IDS["thumb"]].x else 0

    # Other fingers: comparison along the y-axis (if tip is above pip, finger is up)
    for name in ["index", "middle", "ring", "pinky"]:
        fingers[name] = 1 if landmarks[TIP_IDS[name]].y < landmarks[PIP_IDS[name]].y else 0

    return fingers


def lm_to_px(landmark, w, h):
    return int(landmark.x * w), int(landmark.y * h)


def main():
    cap = cv2.VideoCapture(CAM_INDEX)
    cap.set(cv2.CAP_PROP_FRAME_WIDTH, FRAME_W)
    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, FRAME_H)

    prev_mouse_x, prev_mouse_y = pyautogui.position()
    prev_scroll_y = None
    last_left_click = 0.0
    last_right_click = 0.0
    start_time = time.time()

    while True:
        success, frame = cap.read()
        if not success:
            break

        frame = cv2.flip(frame, 1)  # mirror the frame for a more natural interaction
        h, w, _ = frame.shape

        # Manage margins: only consider the central area of the frame for hand detection and mouse control
        cv2.rectangle(
            frame,
            (FRAME_MARGIN, FRAME_MARGIN),
            (w - FRAME_MARGIN, h - FRAME_MARGIN),
            (255, 0, 255),
            2,
        )

        rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        mp_image = mp.Image(image_format=mp.ImageFormat.SRGB, data=rgb)
        timestamp_ms = int((time.time() - start_time) * 1000)
        result = landmarker.detect_for_video(mp_image, timestamp_ms)

        if result.hand_landmarks and result.handedness:
            lm = result.hand_landmarks[0]
            handedness_label = result.handedness[0][0].category_name

            # Draw the hand skeleton (instead of solutions.drawing_utils)
            for connection in HAND_CONNECTIONS:
                x1, y1 = lm_to_px(lm[connection.start], w, h)
                x2, y2 = lm_to_px(lm[connection.end], w, h)
                cv2.line(frame, (x1, y1), (x2, y2), (0, 200, 0), 2)
            for point in lm:
                cv2.circle(frame, lm_to_px(point, w, h), 3, (0, 100, 255), cv2.FILLED)

            fingers = fingers_up(lm, handedness_label)
            index_px = lm_to_px(lm[TIP_IDS["index"]], w, h)
            thumb_px = lm_to_px(lm[TIP_IDS["thumb"]], w, h)
            middle_px = lm_to_px(lm[TIP_IDS["middle"]], w, h)

            total_up = sum(fingers.values())

            # --- Mouse movement: only if the index finger is up ---
            if fingers["index"] == 1 and fingers["middle"] == 0 and total_up <= 2:
                x = np.interp(index_px[0], (FRAME_MARGIN, w - FRAME_MARGIN), (0, SCREEN_W))
                y = np.interp(index_px[1], (FRAME_MARGIN, h - FRAME_MARGIN), (0, SCREEN_H))

                curr_x = prev_mouse_x + (x - prev_mouse_x) / SMOOTHING
                curr_y = prev_mouse_y + (y - prev_mouse_y) / SMOOTHING

                pyautogui.moveTo(curr_x, curr_y)
                prev_mouse_x, prev_mouse_y = curr_x, curr_y
                cv2.circle(frame, index_px, 10, (0, 255, 0), cv2.FILLED)

            # --- Left click: thumb + index finger pinch ---
            dist_thumb_index = math.hypot(thumb_px[0] - index_px[0], thumb_px[1] - index_px[1])
            if dist_thumb_index < CLICK_DISTANCE and time.time() - last_left_click > CLICK_COOLDOWN:
                pyautogui.click()
                last_left_click = time.time()
                cv2.circle(frame, index_px, 15, (0, 0, 255), cv2.FILLED)

            # --- Right click: thumb + middle finger pinch ---
            dist_thumb_middle = math.hypot(thumb_px[0] - middle_px[0], thumb_px[1] - middle_px[1])
            if dist_thumb_middle < CLICK_DISTANCE and time.time() - last_right_click > CLICK_COOLDOWN:
                pyautogui.click(button="right")
                last_right_click = time.time()
                cv2.circle(frame, middle_px, 15, (255, 0, 0), cv2.FILLED)

            # --- Scroll: index + middle fingers both up ---
            if fingers["index"] == 1 and fingers["middle"] == 1 and fingers["ring"] == 0:
                avg_y = (index_px[1] + middle_px[1]) / 2
                if prev_scroll_y is not None:
                    diff = prev_scroll_y - avg_y
                    if abs(diff) > 5:
                        pyautogui.scroll(int(diff * SCROLL_SENSITIVITY / 10))
                prev_scroll_y = avg_y
            else:
                prev_scroll_y = None

        cv2.imshow("Hand Control", frame)

        if cv2.waitKey(1) & 0xFF == 27:  # ESC
            break

    cap.release()
    cv2.destroyAllWindows()


if __name__ == "__main__":
    main()
