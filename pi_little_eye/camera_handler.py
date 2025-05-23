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
import gc
import gevent

from .db_config_handler import *

class CameraHandler:

    def __init__(self, config ):
        self.config = config
        self.camera_running = False
        #Currently supports the first found camera
        self.selected_camera_number = config.get_parameter_value( 'cam_number' )
        self.user_selected_res = ( config.get_parameter_value( 'cam_res_width' ), config.get_parameter_value( 'cam_res_height' ) )
        self.image_rotation_degrees = self.config.get_parameter_value( 'image_rotation' )
        self.timestamp_scale_name = self.config.get_parameter_value( 'timestamp_scale_factor' )
        self.timestamp_position = config.get_parameter_value( 'timestamp_position' )
        self.display_timestamp = config.get_parameter_value( 'display_timestamp' )
        self.camera_state_change_lock = threading.Lock()
        self.frame_publish_lock = threading.Lock()
        self.option_change_lock = threading.Lock()
        self.last_frame = None
        self.logged_in_users = dict()
        self.update_login_lock = threading.Lock()
        # Turn off the verbose camera logging
        Picamera2.set_logging(Picamera2.ERROR)
        os.environ["LIBCAMERA_LOG_LEVELS"] = "ERROR"
        #Enquire about the resolutions the attached camera can do
        self.camera_detected = False
        self.available_resolutions = []
        resolutions = self.__enumerate_resolutions( self.selected_camera_number )
        if resolutions != None and len(resolutions) > 0:
            self.available_resolutions = resolutions
            self.current_resolution = CameraHandler.__suggest_camera_resolution( resolutions, self.user_selected_res )
            self.camera_detected = True

        self.recalculate_timestamp_text_position()

    def publish_image(self):
        with self.frame_publish_lock:
            self.frame_num = -1
        while self.camera_running:
            frame = self.picam2.capture_array()
            frame = cv2.cvtColor(frame, cv2.COLOR_RGBA2RGB)  # Convert XRGB to RGB
            with self.option_change_lock:
               frame = CameraHandler.rotate_image( frame, self.image_rotation_degrees )
               if self.display_timestamp:
                   frame = self.add_timestamp(frame)
            ret, buffer = cv2.imencode('.jpg', frame, [int(cv2.IMWRITE_JPEG_QUALITY), 50] )
            frame = buffer.tobytes()
            with self.frame_publish_lock:
                self.last_frame = frame
                self.frame_num +=1
            # Up to about 30FPS
            time.sleep(0.03)

    def rotate_image( frame, rotation ):
        if rotation == 90:
            return cv2.rotate(frame, cv2.ROTATE_90_CLOCKWISE)
        elif rotation == 180:
            return cv2.rotate(frame, cv2.ROTATE_180)
        elif rotation == 270:
            return cv2.rotate(frame, cv2.ROTATE_90_COUNTERCLOCKWISE)
             
        return frame
        
    def set_new_rotation( self, rotation ):
        if rotation != None and isinstance(rotation, int) and rotation != self.image_rotation_degrees:
            if (rotation <= 270) and ((rotation % 90) == 0):
                with self.option_change_lock:
                    self.image_rotation_degrees = rotation

    def scale_name_to_scale_value( scale_name ):
        new_scaling = float( 1.0 )
        if scale_name == 'small':
            new_scaling = 0.5
        elif scale_name == 'large':
            new_scaling = 1.5
        else:
            scale_name = 'medium'
            new_scaling = 1.0
        
        return new_scaling
                    
    def set_new_timestamp_scale( self, scale_name ):
        with self.option_change_lock:
            self.timestamp_scale_name = scale_name
        
    def set_new_timestamp_position( self, position ):
        with self.option_change_lock:
            self.timestamp_position = position
            
    def set_display_timestamp( self, do_display ):
        with self.option_change_lock:
            self.display_timestamp = do_display
        
    def start_camera(self):
        if self.camera_detected:
            with self.camera_state_change_lock:
                if not self.camera_running:
                    self.picam2 = Picamera2(self.selected_camera_number)
                    self.picam2.configure(self.picam2.create_preview_configuration(main={"format": 'XRGB8888', "size": self.current_resolution}))
                    self.picam2.start()
                    self.camera_running = True
                    time.sleep(0.1)
                    self.capture_thread = threading.Thread(target=self.publish_image)
                    self.capture_thread.start()
                    self.config.write_log_line( 'info', False , '', '', 'camera_started', f"Camera switched on." )
                
            
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
                
                self.config.write_log_line( 'info', False , '', '', 'camera_stopped', f"Camera switched off." )
                

    # Change the camera resolution - can be set whilst the camera is running
    def change_resolution(self, new_resolution):
        #Validate the user input
        if new_resolution is not None and isinstance(new_resolution, (list, tuple)):
            if len( new_resolution ) == 2 and isinstance( new_resolution[0], int) and isinstance( new_resolution[1], int):
                if new_resolution[0] > 128 and new_resolution[1] > 128:
                    #Don't change resolution if it's the same as the current resolutions
                    #Validates the resolution passed in is a mode available on this camera
                    if self.camera_detected:
                        new_resolution = CameraHandler.__suggest_camera_resolution( self.available_resolutions, new_resolution )
                        if new_resolution[0] != self.current_resolution[0] or new_resolution[1] != self.current_resolution[1]:
                            # Set the camera resolution
                            with self.camera_state_change_lock:
                                with self.frame_publish_lock:
                                    if self.camera_running:
                                        new_config = self.picam2.create_still_configuration(main={"format": 'XRGB8888', "size": new_resolution})
                                        self.picam2.switch_mode(new_config)
                            
                            # Update the config with the selected resolution
                            with self.option_change_lock:
                                self.current_resolution = new_resolution
                                self.config.insert_or_update_parameter( 'cam_res_width', 'int', new_resolution[0] )
                                self.config.insert_or_update_parameter( 'cam_res_height', 'int', new_resolution[1] )
                            
                            self.recalculate_timestamp_text_position()

    def is_camera_detected(self):
        return self.camera_detected
    
    # Return the cached version of the available camera resolutions
    def get_camera_resolutions( self ):
        return self.available_resolutions
        
    def get_camera_current_resolutions( self ):
        return self.current_resolution
    
    #Converts the user selected resolution into the nearest actual resolution the camera can do
    def __suggest_camera_resolution( resolution_list, user_res_choice ):
        
        for resolution in resolution_list:
            if resolution[0] >= user_res_choice[0] and resolution[1] >= user_res_choice[1]:
                return resolution
        
        # If we can't find anything suitable, return the first resolution on the list
        return resolutions[0]
        
    def set_config( self, post_data ):
        if post_data is not None and isinstance( post_data, dict):
            if 'selected_resolution' in post_data:
                if isinstance( post_data[ 'selected_resolution' ], (list,tuple) ):
                    self.change_resolution( post_data[ 'selected_resolution' ] )
            if 'image_rotation' in post_data:
                self.set_new_rotation( post_data[ 'image_rotation' ] )
            if 'timestamp_scale' in post_data:
                self.set_new_timestamp_scale( post_data[ 'timestamp_scale' ] )
            if 'timestamp_position' in post_data:
                self.set_new_timestamp_position( post_data[ 'timestamp_position' ] )
            if 'display_timestamp' in post_data:
                self.set_display_timestamp(  post_data[ 'display_timestamp' ] )
            
            self.recalculate_timestamp_text_position()
    
    # Get the resolutions the camera can do  
    # Should be called once on boot           
    def __enumerate_resolutions( self, camera_number ):
        resolutions = []
        
        try:
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
        except:
            return None
        
        return resolutions
        
    def append_camera_current_config(self, config):
        config['available_camera_resolutions'] = self.get_camera_resolutions()
        config['current_camera_resolution'] = self.get_camera_current_resolutions()
        config['is_camera_available'] = self.is_camera_detected()
        return config
    
    # When user config options change, or the resolution changes then change the position of the timestamp text on screen    
    def recalculate_timestamp_text_position( self ):
        timestamp_text = str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        
        with self.option_change_lock:
            timestamp_scale_factor = CameraHandler.scale_name_to_scale_value( self.timestamp_scale_name )
            # Base text size - set for an image resolution of 640x480
            self.timestamp_text_scale = 0.5
            # Scale up or down the text size based on the actual camera resolution setting with reference to the 640x480 base size
            self.timestamp_text_scale *= (self.current_resolution[1] / 480)
            # Further scale up or down the text size based on the user text size config setting       
            self.timestamp_text_scale *= timestamp_scale_factor       

            # Increase the thickness of the font at higher camera resolutions
            self.timestamp_thickness_inner = int((self.current_resolution[1] / 480))
            if self.timestamp_thickness_inner < 1:
                self.timestamp_thickness_inner = 1
            self.timestamp_thickness_outer = self.timestamp_thickness_inner*2    
            
            # Predict the resulting width/height of the timestamp text in pixels so we can calculate the screen position from this
            (text_width, text_height), baseline = cv2.getTextSize(timestamp_text, cv2.FONT_HERSHEY_SIMPLEX, self.timestamp_text_scale, self.timestamp_thickness_outer)
            
            # Amount of padding from the edges of the image based on 640x480 resolution
            top_padding_pixels_at_480 = 3
            side_padding_pixels_at_640 = 1
            
            # Rescale the padding for higher resolutions
            top_padding_resolution_scaled = int(((self.current_resolution[1] / 480)*top_padding_pixels_at_480))
            side_padding_pixels_resolution_scaled = int(((self.current_resolution[0] / 640)*side_padding_pixels_at_640))
            
            image_width = self.current_resolution[0]
            image_height = self.current_resolution[1]
            if self.image_rotation_degrees == 90 or self.image_rotation_degrees == 270:
                image_width = self.current_resolution[1]
                image_height = self.current_resolution[0]
            
            # Position the timestamp text based on the user config selection
            if self.timestamp_position == 'top-left':
                self.timestamp_left_edge = side_padding_pixels_resolution_scaled
                self.timestamp_bottom_edge = text_height + top_padding_resolution_scaled
            elif self.timestamp_position == 'top-right':
                self.timestamp_left_edge = image_width - text_width - side_padding_pixels_resolution_scaled
                self.timestamp_bottom_edge = text_height + top_padding_resolution_scaled
            elif self.timestamp_position == 'bottom-left':
                self.timestamp_left_edge = side_padding_pixels_resolution_scaled
                self.timestamp_bottom_edge = image_height - top_padding_resolution_scaled - 1
            else:
                # Bottom right
                self.timestamp_left_edge = image_width - text_width - side_padding_pixels_resolution_scaled
                self.timestamp_bottom_edge = image_height - top_padding_resolution_scaled - 1            

    def add_timestamp(self, frame):
        timestamp_text = str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        # Text drawn twice to make the font outline - so it's visible on any background colour

        # Draw the text twice, once at a thicker size and once at a thinner size to get an outline effect
        # This improves visibility of the text at all camera constrasts
        cv2.putText(frame, timestamp_text, (self.timestamp_left_edge, self.timestamp_bottom_edge), cv2.FONT_HERSHEY_SIMPLEX, self.timestamp_text_scale, (0, 0, 0), self.timestamp_thickness_outer, cv2.LINE_AA)
        cv2.putText(frame, timestamp_text, (self.timestamp_left_edge, self.timestamp_bottom_edge), cv2.FONT_HERSHEY_SIMPLEX, self.timestamp_text_scale, (255, 255, 255), self.timestamp_thickness_inner, cv2.LINE_AA)
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
                #print( "viewing:"+str(self.logged_in_users[username]) )
            else:
                self.logged_in_users[username] = 1
                #print( "viewing:"+str(self.logged_in_users[username]) )

    def is_user_viewing( self, username ):
        with self.update_login_lock:
            return username in self.logged_in_users
    
    # Returns all users currently viewing the camera and the number of viewing sessions per user
    def get_all_viewing_users( self ):
        with self.update_login_lock:
            deep_copied_dict = copy.deepcopy(self.logged_in_users)
            return deep_copied_dict.items()
    
    def logout_user( self, username ):
        if DBConfigHandler.validate_utf8_string( username, max_length=DBConfigHandler.MAX_USERNAME_LENGTH ):    
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
                    gevent.sleep(0)
                else:
                    # Check for new frames at a slightly faster rate than the camera frame rate
                    #time.sleep(0.01)
                    gevent.sleep(0.01)
               
            yield (b'--frame\r\n'
                   b'Content-Type: image/png\r\n\r\n' + CameraHandler.create_message_image("Logged out") + b'\r\n')
           

        finally:
            with self.update_login_lock:
                if username in self.logged_in_users:
                    self.logged_in_users[username]-=1
                    if self.logged_in_users[username] < 1:
                        del self.logged_in_users[username]
                        self.config.write_log_line( 'info', False , username, '', 'disconnect', f"Stopped viewing camera." )
                    else:
                        self.config.write_log_line( 'info', False , username, '', 'disconnect', f"Session disconnected." )
            
            if self.get_total_num_viewing_sessions() < 1:
                self.stop_camera()
            
