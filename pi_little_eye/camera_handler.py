import cv2
import numpy as np

from gevent import GreenletExit
from datetime import datetime, timedelta
from picamera2 import Picamera2
from functools import wraps
import threading
import time
import copy
import os
import gc
import gevent
import logging
import io
from multiprocessing import get_context, shared_memory

from PIL import Image, ImageDraw


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
        Picamera2.set_logging(logging.ERROR)
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
                       
        ctx = get_context("spawn")  # explicit spawn: fresh interpreter, no inherited state
        self.bg_shared_mem = shared_memory.SharedMemory(create=True, size=4*1024*1024)
        self.frame_len = ctx.Value("i", 0)   # length in bytes of the current frame
        self.frame_id = ctx.Value("i", -1)    # bumped every time a new frame is published
        self.frame_gen_lock = ctx.Lock()

        cam = ctx.Process(
            target=CameraHandler.bg_image_producer,
            args=(self.bg_shared_mem.name, self.frame_gen_lock, self.frame_len, self.frame_id, self.current_resolution, self.selected_camera_number ),
            daemon=True,
        )
        cam.start()

   
    @staticmethod
    def bg_image_producer(shm_name: str, lock, frame_len, frame_id, init_resolution, init_camera_num):
        shm = shared_memory.SharedMemory(name=shm_name)
        running = True
        fps = 30
        fid = 0
        
        picam2 = Picamera2(init_camera_num)
        
        # 1. YUV420 uses 62.5% LESS memory than XRGB8888.
        # Essential for 512MB RAM on Pi Zero 2W to prevent SD card swap thrashing.
        config = picam2.create_preview_configuration(
            main={"format": 'YUV420', "size": init_resolution},
            controls={"FrameDurationLimits": (int(1000000 / fps), int(1000000 / fps))}
        )
        picam2.configure(config)
        picam2.start()
        
        try:
            while running:
                start_time = time.time()
                
                # 2. Picamera2 native C++ JPEG encoder (NEON SIMD accelerated).
                # Encodes directly into memory without OpenCV or NumPy overhead.
                buf = io.BytesIO()
                picam2.capture_file(buf, format='jpeg')
                frame_bytes = buf.getvalue()
                frame_size = len(frame_bytes)
                
                # 3. Write JPEG bytes to shared memory
                if 0 < frame_size <= len(shm.buf):
                    with lock:
                        shm.buf[:frame_size] = frame_bytes
                        frame_len.value = frame_size
                        fid += 1
                        frame_id.value = fid
                
                # Rate limiting
                elapsed = time.time() - start_time
                remaining_delay = (1.0 / fps) - elapsed
                if remaining_delay > 0:
                    time.sleep(remaining_delay)
                else:
                    time.sleep(0.001)
                    
        finally:
            picam2.stop()
            shm.close()

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
        config['is_camera_available'] = self.is_camera_detected()
        if self.is_camera_detected():
            config['available_camera_resolutions'] = self.get_camera_resolutions()
            config['current_camera_resolution'] = self.get_camera_current_resolutions()
        return config
    
    # When user config options change, or the resolution changes then change the position of the timestamp text on screen    
    def recalculate_timestamp_text_position(self):
        timestamp_text = str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        with self.option_change_lock:
            timestamp_scale_factor = CameraHandler.scale_name_to_scale_value(self.timestamp_scale_name)
            self.timestamp_text_scale = 0.5
            self.timestamp_text_scale *= (self.current_resolution[1] / 480)
            self.timestamp_text_scale *= timestamp_scale_factor

            self.timestamp_thickness_inner = int((self.current_resolution[1] / 480))
            if self.timestamp_thickness_inner < 1:
                self.timestamp_thickness_inner = 1
            self.timestamp_thickness_outer = self.timestamp_thickness_inner * 2

            (text_width, text_height), baseline = cv2.getTextSize(
                timestamp_text, cv2.FONT_HERSHEY_SIMPLEX,
                self.timestamp_text_scale, self.timestamp_thickness_outer
            )

            top_padding_pixels_at_480 = 1
            side_padding_pixels_at_640 = 1
            top_padding_resolution_scaled = int(((self.current_resolution[1] / 480) * top_padding_pixels_at_480))
            side_padding_pixels_resolution_scaled = int(((self.current_resolution[0] / 640) * side_padding_pixels_at_640))

            image_width = self.current_resolution[0]
            image_height = self.current_resolution[1]
            if self.image_rotation_degrees == 90 or self.image_rotation_degrees == 270:
                image_width = self.current_resolution[1]
                image_height = self.current_resolution[0]

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
                self.timestamp_left_edge = image_width - text_width - side_padding_pixels_resolution_scaled
                self.timestamp_bottom_edge = image_height - top_padding_resolution_scaled - 1

            # Precompute the dilation kernel once here rather than every frame in add_timestamp()
            outline_width = max(1, self.timestamp_thickness_outer - self.timestamp_thickness_inner)
            self.timestamp_outline_kernel = cv2.getStructuringElement(
                cv2.MORPH_ELLIPSE, (outline_width * 2 + 1, outline_width * 2 + 1)
            )
            # Small bounding-box padding for the mask ROI (covers dilation + AA overhang)
            self.timestamp_mask_pad = outline_width * 3 + 4

    def add_timestamp(self, frame):
        timestamp_text = str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        x0, y0 = self.timestamp_left_edge, self.timestamp_bottom_edge
        (text_w, text_h), baseline = cv2.getTextSize(
            timestamp_text, cv2.FONT_HERSHEY_SIMPLEX, self.timestamp_text_scale, self.timestamp_thickness_outer
        )
        pad = self.timestamp_mask_pad
        x_min = max(x0 - pad, 0)
        y_min = max(y0 - text_h - pad, 0)
        x_max = min(x0 + text_w + pad, frame.shape[1])
        y_max = min(y0 + baseline + pad, frame.shape[0])

        roi = frame[y_min:y_max, x_min:x_max]
        local_org = (x0 - x_min, y0 - y_min)

        mask = np.zeros(roi.shape[:2], dtype=np.uint8)
        cv2.putText(mask, timestamp_text, local_org, cv2.FONT_HERSHEY_SIMPLEX,
                    self.timestamp_text_scale, 255, self.timestamp_thickness_inner, cv2.LINE_AA)

        outline_mask = cv2.dilate(mask, self.timestamp_outline_kernel)

        outline_alpha = (outline_mask.astype(np.float32) / 255.0)[..., None]
        roi[:] = (roi * (1 - outline_alpha)).astype(np.uint8)

        fill_alpha = (mask.astype(np.float32) / 255.0)[..., None]
        roi[:] = (roi * (1 - fill_alpha) + 255 * fill_alpha).astype(np.uint8)

        frame[y_min:y_max, x_min:x_max] = roi
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
    
    """
        Tear and stream stop problem:
        
        OK, the issue was that you're exceeding the pi wi-fi bandwidth.
        Pi Zero 2W max theoretical network capacity = 72.2Mbps.
        Practically it is 40% of this.
        Peak throughput 2.75 = 4.4Mbytes/s
        When you open two video streams at max resolution, this is exceededing the network bandwidth massively.
        
        There was a bug in the JavaScript where you opened two streams simultaneously by mistake for each UI.
        This caused the bandwidth to be exceeded and then it cancelled the stream.
        
        The bug is now fixed and you only open one stream at once.
        However if you have two sessions running then you exceed the bandwidth again
        So need to dial back the frame rate as more streams are opened.
        
        You need to get maximum capacity of pi network on different models of pi and dial down the image size so it fits the model
        Pi 4 and 5 have much better bandwdith than the zero.
        Reduce the compression.
        Divide down the network capacity by the number of users.
        
    """
    
    def generate_camera_video(self, username):            
        username = username.lower()
        self.add_viewing_user(username)

        try:
            last_posted_frame = -1
            
            while self.is_user_viewing(username):
                new_frame = False
                
                # 1. Check if a new frame ID exists
                if self.frame_id.value > 0 and last_posted_frame < self.frame_id.value:
                    
                    # 2. Try to acquire lock BEFORE touching last_posted_frame
                    if self.frame_gen_lock.acquire(block=False):
                        try:
                            length = self.frame_len.value
                            raw_bytes = self.bg_shared_mem.buf[:length]
                            
                            # 3. VERIFY JPEG INTEGRITY (Must start with 0xFFD8 and end with 0xFFD9)
                            if length > 4 and raw_bytes[:2] == b'\xff\xd8' and raw_bytes[-2:] == b'\xff\xd9':
                                frame = bytes(raw_bytes)
                                last_posted_frame = self.frame_id.value  # Only update on valid read
                                new_frame = True
                                print(len(frame))
                                print( length )
                            else:
                                print(f"[WARN] Incomplete/torn JPEG in shared memory (len: {length}). Skipping.")
                        finally:
                            self.frame_gen_lock.release()

                if new_frame:

                    payload = (
                        b"--frame\r\n"
                        b"Content-Type: image/jpeg\r\n\r\n" + frame + b"\r\n"
                    )
                    yield payload
                    gevent.sleep(0.03)  # Sleep ONCE per full frame
                    

                    
                else:
                    gevent.sleep(0.01)
                   
            #yield (b'--frame\r\n'
            #       b'Content-Type: image/png\r\n\r\n' + CameraHandler.create_message_image("Logged out") + b'\r\n')
        except (GeneratorExit, GreenletExit):
            print("EXIT")
            return
        finally:
            with self.update_login_lock:
                if username in self.logged_in_users:
                    self.logged_in_users[username] -= 1
                    if self.logged_in_users[username] < 1:
                        del self.logged_in_users[username]
                        self.config.write_log_line('info', False, username, '', 'disconnect', "Stopped viewing camera.")
                    else:
                        self.config.write_log_line('info', False, username, '', 'disconnect', "Session disconnected.")
    
 
