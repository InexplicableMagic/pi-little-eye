import cv2
import numpy as np

from datetime import datetime, timedelta
from picamera2 import Picamera2
import RPi.GPIO as GPIO
from functools import wraps
import threading
import time
import copy
import os

class CameraHandler:

    def __init__(self):
        self.camera_running = False
        #Currently supports the first found camera
        self.selected_camera_number = 0
        self.camera_state_change_lock = threading.Lock()
        self.frame_publish_lock = threading.Lock()
        self.last_frame = None
        self.logged_in_users = dict()
        self.update_login_lock = threading.Lock()
        # Turn off the verbose camera logging
        Picamera2.set_logging(Picamera2.ERROR)
        os.environ["LIBCAMERA_LOG_LEVELS"] = "ERROR"
        #Enquire about the resolutions the attached camera can do
        self.available_resolutions = self.__enumerate_resolutions( self.selected_camera_number )

    def publish_image(self):
        with self.frame_publish_lock:
            self.frame_num = -1
        while self.camera_running:
            frame = self.picam2.capture_array()
            frame = cv2.cvtColor(frame, cv2.COLOR_RGBA2RGB)  # Convert XRGB to RGB
            frame = CameraHandler.add_timestamp(frame)
            ret, buffer = cv2.imencode('.jpg', frame)
            frame = buffer.tobytes()
            with self.frame_publish_lock:
                self.last_frame = frame
                self.frame_num +=1
            # Up to about 30FPS
            time.sleep(0.03)
        
    def start_camera(self):
        with self.camera_state_change_lock:
            if not self.camera_running:
                self.picam2 = Picamera2(self.selected_camera_number)
                self.picam2.configure(self.picam2.create_preview_configuration(main={"format": 'XRGB8888', "size": (640, 480)}))
                self.picam2.start()
                self.camera_running = True
                time.sleep(0.1)
                self.capture_thread = threading.Thread(target=self.publish_image)
                self.capture_thread.start()
                
            
    def stop_camera(self):
        with self.camera_state_change_lock:
            if self.camera_running and self.picam2 is not None:
                self.camera_running = False
                self.capture_thread.join()
                with self.frame_publish_lock:
                     self.last_frame = None
                     self.frame_num = -1

                self.picam2.stop()
                self.picam2.close()
    
    # Return the cached version of the available camera resolutions
    def get_camera_resolutions():
        return self.available_resolutions
    
    # Get the resolutions the camera can do             
    def __enumerate_resolutions( self, camera_number ):
        resolutions = []
        
        with self.camera_state_change_lock:
            if self.camera_running:
                pc2 = self.picam2
            else:
                pc2 = Picamera2(camera_number)
            sensor_modes = pc2.sensor_modes
            for camfmt in sensor_modes:
                if 'size' in camfmt:
                    resolutions.append( camfmt['size'] )
        
            if not self.camera_running:
                pc2.close()
        
        return resolutions

    def add_timestamp(frame):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # Text drawn twice to make the font outline - so it's visible on any background colour
        cv2.putText(frame, timestamp, (5, 20), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 0, 0), 2, cv2.LINE_AA)
        cv2.putText(frame, timestamp, (5, 20), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 1, cv2.LINE_AA)
        return frame
    
    # Returns an image with some text on it for debugging
    def create_message_image(text):
        img = np.zeros((150, 640, 3), np.uint8)
        font = cv2.FONT_HERSHEY_SIMPLEX
        textsize = cv2.getTextSize(text, font, 1, 2)[0]
        textX = (img.shape[1] - textsize[0]) // 2
        textY = (img.shape[0] + textsize[1]) // 2
        cv2.putText(img, text, (textX, textY), font, 1, (0, 0, 255), 2, cv2.LINE_AA)
        ret, buffer = cv2.imencode('.png', img)
        return buffer.tobytes()
    
    def add_viewing_user( self, username ):
        username = username.lower()
        with self.update_login_lock:
            if username in self.logged_in_users:
                self.logged_in_users[username]+=1
                print( "viewing:"+str(self.logged_in_users[username]) )
            else:
                self.logged_in_users[username] = 1
                print( "viewing:"+str(self.logged_in_users[username]) )

    def is_user_viewing( self, username ):
        with self.update_login_lock:
            return username in self.logged_in_users
    
    # Returns all users currently viewing the camera and the number of viewing sessions per user
    def get_all_viewing_users( self ):
        with self.update_login_lock:
            deep_copied_dict = copy.deepcopy(self.logged_in_users)
            return deep_copied_dict.items()
    
    def logout_user( self, username ):
        username = username.lower()
        with self.update_login_lock:
            if username in self.logged_in_users:
                del self.logged_in_users[username]
               
    def get_total_num_viewing_sessions( self ):
        with self.update_login_lock:
            return sum(self.logged_in_users.values())
    
    def generate_camera_video(self, username):            
        username = username.lower()
        self.add_viewing_user( username )
        self.start_camera()    
        try:
            last_posted_frame = -1
            new_frame = False
            
            #If the user has not been logged out
            while self.is_user_viewing( username ):
            
                #Each frame has a frame number
                #Check if there is a new frame number published since last time we checked
                with self.frame_publish_lock:
                    if self.last_frame is not None:
                        if self.frame_num > 0 and last_posted_frame < self.frame_num:
                            frame = self.last_frame
                            last_posted_frame = self.frame_num
                            new_frame = True
                
                if new_frame:
                    new_frame = False
                    yield (b'--frame\r\n'
                           b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')
                else:
                    # Check for new frames at a slightly faster rate than the camera frame rate
                    time.sleep(0.01)
               
            yield (b'--frame\r\n'
                   b'Content-Type: image/png\r\n\r\n' + CameraHandler.create_message_image("Logged out") + b'\r\n')

        finally:
            with self.update_login_lock:
                if username in self.logged_in_users:
                    self.logged_in_users[username]-=1
                    if self.logged_in_users[username] < 1:
                        del self.logged_in_users[username]
            
            if self.get_total_num_viewing_sessions() < 1:
                self.stop_camera()
