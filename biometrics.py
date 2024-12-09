import threading
import cv2 
from deepface import DeepFace

def recognize_face():
  reference_img = "reference.jpg"
  cap = cv2.VideoCapture(0)
  frame_count = 0
  check_interval = 30

  while True:
    ret, frame = cap.read()
    if not ret:
      break

    if frame_count % check_interval == 0:
      try:
        result = DeepFace.verify(frame, reference_img)
        if result["verified"]:
          text = "Face recognized!"
        else:
          text = "Face not recognized."
      except Exception as e:
        text = "Face not recognized."

    # Display the result on the video feed
    cv2.putText(frame, text, (50, 50), cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 255, 0), 2, cv2.LINE_AA)
    cv2.imshow('Video Feed', frame)

    if cv2.waitKey(1) & 0xFF == ord('q'):
      break

    frame_count += 1

  cap.release()
  cv2.destroyAllWindows()

if __name__ == "__main__":
  recognize_face()