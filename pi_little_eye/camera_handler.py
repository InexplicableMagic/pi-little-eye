import os

import cv2
import numpy as np
from datetime import datetime, timedelta
from picamera2 import Picamera2
from libcamera import controls, Transform
from functools import wraps
import threading
import time
import copy
import gc
import logging
import io
import signal
from multiprocessing import get_context, shared_memory, Pipe

from PIL import Image, ImageDraw

from .db_config_handler import *

class CameraHandler:

    def __init__(self, config ):
        self.config = config
        self.camera_paused = True
        #Currently supports the first found camera
        self.selected_camera_number = config.get_parameter_value( 'cam_number' )
        self.user_selected_res = ( config.get_parameter_value( 'cam_res_width' ), config.get_parameter_value( 'cam_res_height' ) )
        self.image_rotation_degrees = self.config.get_parameter_value( 'image_rotation' )
        self.timestamp_scale_name = self.config.get_parameter_value( 'timestamp_scale_factor' )
        self.timestamp_position = config.get_parameter_value( 'timestamp_position' )
        self.display_timestamp = config.get_parameter_value( 'display_timestamp' )
        self.camera_state_change_lock = threading.Lock()
        self.option_change_lock = threading.Lock()
        self.update_login_lock = threading.Lock()
        self.last_frame = None
        self.logged_in_users = dict()
        # Turn off the verbose camera logging
        Picamera2.set_logging(logging.ERROR)
        os.environ["LIBCAMERA_LOG_LEVELS"] = "ERROR"
        #Enquire about the resolutions the attached camera can do
        self.camera_detected = False
        self.available_resolutions = []
        resolutions = self.__enumerate_resolutions( self.selected_camera_number )
        self.resolutions_wh = []
        # Resolutions as a simple list of widths and heights
        if resolutions != None and len(resolutions) > 0:
            self.resolutions_wh = CameraHandler.resolutions_to_width_height_list( resolutions )
            self.available_resolutions = resolutions
            self.current_resolution = CameraHandler.__suggest_camera_resolution( resolutions, self.user_selected_res )
            self.camera_detected = True
                       
            ctx = get_context("spawn")  # explicit spawn: fresh interpreter, no inherited state
            self.bg_shared_mem = shared_memory.SharedMemory(create=True, size=4*1024*1024)
            self.frame_len = ctx.Value("i", 0)   # length in bytes of the current frame
            self.frame_id = ctx.Value("i", -1)    # bumped every time a new frame is published
            self.frame_gen_lock = ctx.Lock()

            self.camera_control_pipe, child_cam_control_pipe = Pipe()
            
            camera_initial_params = self.generate_camera_parameter_message(camera_restart=True)
            self.camera_process = ctx.Process(
                target=CameraHandler.bg_image_producer,
                args=(self.bg_shared_mem.name, self.frame_gen_lock, self.frame_len, self.frame_id, child_cam_control_pipe, camera_initial_params ),
                daemon=False,
            )
            self.camera_process.start()  
        
    def generate_camera_parameter_message( self, camera_restart=False ):
        cam_param_block = {
            'selected_resolution': self.current_resolution,
            'available_resolutions' : self.available_resolutions,
            'selected_camera_number': self.selected_camera_number,
            'timestamp_position': self.timestamp_position,
            'timestamp_scale_name': self.timestamp_scale_name,
            'display_timestamp': self.display_timestamp,
            'rotation': self.image_rotation_degrees,
            'jpeg_quality': 70,
            'camera_restart': camera_restart
        }
        
        return cam_param_block
        
    def pause_camera( self, new_state ):
        with self.camera_state_change_lock:
            if new_state != self.camera_paused:
                self.camera_paused = new_state
                msg = {
                    'paused': new_state
                }
                self.camera_control_pipe.send( msg )
                
    def close_down( self ):
    
        # Close down background process that generates camera frames
        with self.camera_state_change_lock:
            msg = { 'stop': True }
            self.camera_control_pipe.send( msg )
        self.camera_process.join( timeout=5 )
        if self.camera_process.is_alive():
            self.camera_process.terminate()
            self.camera_process.join( timeout=1 )  # Reclaim PID from process table
            
        # Close down shared memory used to transmit frames from the camera
        try:
            self.bg_shared_mem.close()
            self.bg_shared_mem.unlink()
        except Exception:
            pass
            
    @staticmethod
    def camera_reset_close(picam2):
        try:
            if picam2 is not None:
                picam2.cancel_all_and_flush()
                picam2.stop()
                picam2.close()
        except Exception:
            pass

    @staticmethod
    def raise_timeout(signum, frame):
        raise TimeoutError("capture_array() timed out")
    
    # Starts in the paused state and then needs waking up to generate images
    @staticmethod
    def bg_image_producer(shm_name: str, lock, frame_len, frame_id, control_pipe, params):
        running = True
        shm = shared_memory.SharedMemory(name=shm_name)
        # Max FPS to ever use
        max_fps=30
        # Actual camera setting as some resolutions can't run at the max
        camera_fps = max_fps
        fid = 0
        parameter_change = True
        rotate_fn = None
        picam2 = None
        paused = True

        signal.signal(signal.SIGALRM, CameraHandler.raise_timeout)
               
        try:
            while running:
                start_time = time.time()
                
                if control_pipe.poll(0):
                    msg = control_pipe.recv()
                    if msg is not None:
                        if 'paused' in msg:
                            paused = msg['paused']
                        elif 'stop' in msg:
                            if msg['stop']:
                                running = False
                        else:
                            params = msg
                            parameter_change = True
                    
                if parameter_change or picam2 is None:
                    # Assumed parameters are validated by this point
                    
                    #Changing resolution requires a camera restart
                    if params['camera_restart'] == True or picam2 is None:
                        #Stop and restart camera with new parameters
                        if picam2 is not None:
                            CameraHandler.camera_reset_close(picam2)

                        try:                        
                            picam2 = Picamera2(params['selected_camera_number'])
                            
                            # Determine the FPS the sensor can do at this resolution and lock the FPS to that
                            max_hardware_fps = params['selected_resolution']['max_fps']
                            camera_fps = min(max_fps, max_hardware_fps)
                            # If the user has requested a 180 degree rotation, we can do that in hardware and save CPU
                            # For other rotations it will have to be done in software which is more expensive
                            if params['rotation'] == 180:
                                transform=Transform(hflip=1, vflip=1)
                            else:
                                transform=Transform(hflip=0, vflip=0)
                            config = picam2.create_preview_configuration(
                                main={  "format": 'YUV420', "size": params['selected_resolution']['resolution'] },
                                raw={"size": params['selected_resolution']['sensor_raw']},
                                transform=transform
                            )
                            controls_to_set = {"FrameRate": camera_fps}
                            # Set autofocus on if the camera supports it
                            if "AfMode" in picam2.camera_controls:
                                controls_to_set["AfMode"] = controls.AfModeEnum.Continuous
                                controls_to_set["AfSpeed"] = controls.AfSpeedEnum.Normal

                            picam2.configure(config)
                            picam2.set_controls(controls_to_set)
                        except Exception as e:
                            # On error - try resetting the camera resolution to the minimum
                            # User may have selected too high a resolution
                            CameraHandler.camera_reset_close(picam2)
                            picam2 = None
                            params['selected_resolution'] = params['available_resolutions'][0]
        
                    timestamp_params = CameraHandler.recalculate_timestamp_text_position( params['timestamp_scale_name'], params['selected_resolution']['resolution'][0] ,params['selected_resolution']['resolution'][1] , params['rotation'], params['timestamp_position'] )
                    parameter_change = False
                
                if not paused:
                    if picam2 is not None:

                        try:
                            if not picam2.started:
                                picam2.start()

                            # Capture crashes in picamera2
                            # Set a 5 second timer which is cancelled if capture_array successfully generates an image
                            # If the timer is triggered, it generates an exception which falls to the outer try/except
                            # and resets the camera at the minimum resolution
                            signal.setitimer(signal.ITIMER_REAL, 5.0)
                            try:
                                yuv_frame = picam2.capture_array()
                            finally:
                                signal.setitimer(signal.ITIMER_REAL, 0)                            
          
                            # Convert full buffer (with padding) to BGR
                            frame = cv2.cvtColor(yuv_frame, cv2.COLOR_YUV2BGR_I420)

                            # The camera outputted image can be wider than the sensor area due to the inclusion of padding for memory alignment
                            # This crops the image down to the actual user specified resolution
                            config_height = params['selected_resolution']['resolution'][1]
                            config_width = params['selected_resolution']['resolution'][0]
                            frame = frame[:config_height, :config_width]

                            # Perform software image rotation for 90 and 270 degrees as cannot do it in hardware
                            if params['rotation'] == 90:
                                frame = cv2.rotate(frame, cv2.ROTATE_90_CLOCKWISE)
                            elif params['rotation'] == 270:
                                frame = cv2.rotate(frame, cv2.ROTATE_90_COUNTERCLOCKWISE)                           

                            # Apply timestamp overlay if requested by user
                            if params['display_timestamp']:
                                frame = CameraHandler.add_timestamp(frame, timestamp_params)
                            
                            # Encode image in JPEG
                            success, encoded = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, params['jpeg_quality']])
                            
                            if not success:
                                # Skip frame if encoding fails
                                time.sleep(0.001)
                                continue
                            
                            frame_bytes = encoded.tobytes()
                            
                            frame_size = len(frame_bytes)
                            
                            # Write JPEG bytes to shared memory
                            if 0 < frame_size <= len(shm.buf):
                                with lock:
                                    shm.buf[:frame_size] = frame_bytes
                                    frame_len.value = frame_size
                                    fid += 1
                                    frame_id.value = fid

                        except Exception as e:
                            # On error - try resetting the camera resolution to the minimum resolution
                            # The most likely reason to get here is the user set too high a resolution
                            # for the pi to handle and it ran out of memory or otherwise crashed
                            CameraHandler.camera_reset_close(picam2)
                            picam2 = None
                            params['selected_resolution'] = params['available_resolutions'][0]
                    
                    # Rate limiting to max FPS of the camera
                    elapsed = time.time() - start_time
                    remaining_delay = (1.0 / camera_fps) - elapsed
                    if remaining_delay > 0:
                        time.sleep(remaining_delay)
                    else:
                        time.sleep(0.001)
                else:
                    # We are paused
                    # Stop camera if previously started but don't close it
                    try:
                        if picam2 is not None:
                            if picam2.started:
                                picam2.cancel_all_and_flush()
                                picam2.stop()
                    except Exception:
                        pass
                    time.sleep(0.1)
                    
        finally:
            CameraHandler.camera_reset_close(picam2)
            shm.close()

    def __set_new_rotation( self, rotation ):
        camera_restart_required = False
        if rotation != None and isinstance(rotation, int) and rotation != self.image_rotation_degrees:
            if (rotation <= 270) and ((rotation % 90) == 0):
                with self.option_change_lock:
                    # If the selected rotation is 180 degrees, this can be done in hardware
                    # but requires a camera restart. The return of True is to signify this
                    if rotation == 180 and (self.image_rotation_degrees != 180):
                         camera_restart_required = True
                    if rotation == 0 and (self.image_rotation_degrees != 0):
                         camera_restart_required = True
                    self.image_rotation_degrees = rotation
                    
        # Software rotation which does not require a camera restart
        return camera_restart_required

    @staticmethod
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
                    
    def __set_new_timestamp_scale( self, scale_name ):
        with self.option_change_lock:
            self.timestamp_scale_name = scale_name
        
    def __set_new_timestamp_position( self, position ):
        with self.option_change_lock:
            self.timestamp_position = position
            
    def __set_display_timestamp( self, do_display ):
        with self.option_change_lock:
            self.display_timestamp = do_display

    def post_camera_options_change( self, camera_restart=False ):
        msg = self.generate_camera_parameter_message(camera_restart)
        self.camera_control_pipe.send( msg )

    # Change the camera resolution - can be set whilst the camera is running
    def __change_resolution(self, new_resolution):
        #Validate the user input
        if new_resolution is not None and isinstance(new_resolution, (list, tuple)):
            if len( new_resolution ) == 2 and isinstance( new_resolution[0], int) and isinstance( new_resolution[1], int):
                if new_resolution[0] > 128 and new_resolution[1] > 128:
                    #Don't change resolution if it's the same as the current resolutions
                    #Validates the resolution passed in is a mode available on this camera
                    if self.camera_detected:
                        new_resolution = CameraHandler.__suggest_camera_resolution( self.available_resolutions, new_resolution )
                        if new_resolution['resolution'][0] != self.current_resolution['resolution'][0] or new_resolution['resolution'][1] != self.current_resolution['resolution'][1]:                            
                            # Update the config with the selected resolution
                            with self.option_change_lock:
                                self.current_resolution = new_resolution
                                self.config.insert_or_update_parameter( 'cam_res_width', 'int', new_resolution['resolution'][0] )
                                self.config.insert_or_update_parameter( 'cam_res_height', 'int', new_resolution['resolution'][1] )
                            return True
        return False
                            

    def is_camera_detected(self):
        return self.camera_detected
            
    #Converts the user selected resolution into the nearest actual resolution the camera can do
    def __suggest_camera_resolution( resolution_list, user_res_choice ):
        
        for resolution in resolution_list:
            if resolution['resolution'][0] >= user_res_choice[0] and resolution['resolution'][1] >= user_res_choice[1]:
                return resolution
        
        # If we can't find anything suitable, return the first resolution on the list
        return resolutions[0]
    
    # Takes a posted config change from the UI and converts it into settings changes
    def set_config( self, post_data ):
        camera_restart_required = False
        if post_data is not None and isinstance( post_data, dict):
            if 'selected_resolution' in post_data:
                if isinstance( post_data[ 'selected_resolution' ], (list,tuple) ):
                    camera_restart_required = self.__change_resolution( post_data[ 'selected_resolution' ] )
            if 'image_rotation' in post_data:
                camera_restart_required = self.__set_new_rotation( post_data[ 'image_rotation' ] )
            if 'timestamp_scale' in post_data:
                self.__set_new_timestamp_scale( post_data[ 'timestamp_scale' ] )
            if 'timestamp_position' in post_data:
                self.__set_new_timestamp_position( post_data[ 'timestamp_position' ] )
            if 'display_timestamp' in post_data:
                self.__set_display_timestamp(  post_data[ 'display_timestamp' ] )
            
            self.post_camera_options_change(camera_restart=camera_restart_required)
            
    
    # Get the resolutions the camera can do  
    # Called once on boot and must be called before background thread starts
    def __enumerate_resolutions( self, camera_number ):
        resolutions = []
        
        try:
            pc2 = Picamera2(camera_number)
            sensor_modes = pc2.sensor_modes
            for camfmt in sensor_modes:
                # Some of the native modes are cropped. Specify which ones are not
                cropped = False
                if 'crop_limits' in camfmt:
                    if camfmt['crop_limits'][0] != 0 or camfmt['crop_limits'][1] != 0:
                        cropped = True
                if 'size' in camfmt:
                    resolutions.append( { 'resolution': camfmt['size'], 'max_fps': camfmt['fps'], 'native': True, 'cropped': cropped, 'sensor_raw': camfmt['size'] } )
            pc2.close()

            if len( resolutions ) < 1:
                return None


            resolutions = CameraHandler.sort_resolutions_by_area( resolutions )

            aspect_ratio_str = CameraHandler.classify_aspect_ratio( resolutions[-1]['resolution'][0] , resolutions[-1]['resolution'][1] )
            resolutions = CameraHandler.append_additional_resolutions( resolutions, aspect_ratio_str )
            resolutions = CameraHandler.sort_resolutions_by_area( resolutions )
            print(resolutions)
            
        except:
            return None
        
        return resolutions

    def sort_resolutions_by_area(resolutions):
        resolutions.sort(key=lambda x: x['resolution'][0] * x['resolution'][1])
        return resolutions

    # Get the camera aspect ratio
    @staticmethod
    def classify_aspect_ratio(width, height, tolerance=0.01):
        target_ratio = width / height
        
        # Target decimals
        ratios = {
            "16:9": 16 / 9,   # ~1.7778
            "4:3": 4 / 3,     # ~1.3333
            "16:10": 16 / 10, # 1.6
            "1:1": 1.0
        }
        
        for name, ideal_value in ratios.items():
            if abs(target_ratio - ideal_value) <= tolerance:
                return name

        # Camera has unknown resolution - try 4x3
        return "4:3"

    # Find out if a resolution already exists in the resolution list
    @staticmethod
    def res_already_exists(resolutions, target_resolution):
        for resolution in resolutions:
            if resolution['resolution'][0] == target_resolution[0] and resolution['resolution'][1] == target_resolution[1]:
                return True
        return False

    # Determine the native FPS and sensor resolution from which a resolution is derived
    @staticmethod
    def get_nearest_fps(resolutions, target_resolution):
        if len(resolutions) == 1:
            return (resolutions[0]['max_fps'], resolutions[0]['resolution'])
            
        target_w, target_h = target_resolution
        
        # Find the resolution item with the minimum squared Euclidean distance
        for resolution in resolutions:
            if resolution['resolution'][0] >= target_w and resolution['resolution'][1] >= target_h and not resolution['cropped']:
               return (resolution['max_fps'], resolution['resolution'])
        
        return (resolutions[-1]['max_fps'], resolutions[-1]['resolution'])

    @staticmethod
    def resolutions_to_width_height_list( resolution_list ):
        wh_list = []
        for resolution in resolution_list:
            wh_list.append( resolution['resolution'] )
        return wh_list

    # Append a selection of standard lower resolutions that can be scaled
    # on the Pi's ISP
    @staticmethod
    def append_additional_resolutions( resolution_list, aspect_ratio ):
        additional_resolutions = {
            "16:9": [
                {'resolution': (640, 360), 'max_fps': 30},   # nHD
                {'resolution': (854, 480), 'max_fps': 30},   # FWVGA
                {'resolution': (960, 540), 'max_fps': 30,},  # qHD
                {'resolution': (1280, 720), 'max_fps': 30},  # HD standard
                {'resolution': (1920, 1080), 'max_fps': 30}, # HD full
            ],
            "4:3": [
                {'resolution': (640, 480), 'max_fps': 30},   # VGA
                {'resolution': (800, 600), 'max_fps': 30},   # SVGA
                {'resolution': (1024, 768), 'max_fps': 30},  # XGA
                {'resolution': (1280, 960), 'max_fps': 30},  # SXGA
                {'resolution': (1600, 1200), 'max_fps': 30}, # UXGA
            ],
            "16:10": [
                {'resolution': (1024, 600), 'max_fps': 30},  # WSVGA
                {'resolution': (1280, 800), 'max_fps': 30},  # WXGA
                {'resolution': (1440, 900), 'max_fps': 30},  # WXGA+
                {'resolution': (1680, 1050), 'max_fps': 30}, # WSXGA+
                {'resolution': (1920, 1200), 'max_fps': 30}, # WUXGA
            ],
            "1:1": [
                {'resolution': (640, 640), 'max_fps': 30},   # VGA Square
                {'resolution': (800, 800), 'max_fps': 30},   # SVGA Square
                {'resolution': (960, 960), 'max_fps': 30},   # HD Square
                {'resolution': (1280, 1280), 'max_fps': 30}, # Megapixel Square
                {'resolution': (1536, 1536), 'max_fps': 30}, # High-density square
            ]
        }

        additional_res_list = additional_resolutions['4:3']       

        if aspect_ratio in additional_resolutions:
            additional_res_list = additional_resolutions[aspect_ratio]

        # Find the next highest, non-cropped native sensor resolution that is higher than the proposed scaled resolution
        # Also discover the max FPS that sensor can do at that resolution.
        for resolution in additional_res_list:
            resolution['max_fps'], resolution['sensor_raw'] = CameraHandler.get_nearest_fps( resolution_list,  resolution['resolution'] )
            resolution['native'] = False
            resolution['cropped'] = False

        # Remove duplicates from the resolution list
        deduplicated_resolution_list = []
        deduplicated_resolution_list.extend( resolution_list )
        for resolution in additional_res_list:
            if not CameraHandler.res_already_exists( resolution_list, resolution['resolution'] ):
                deduplicated_resolution_list.append( resolution )

        return deduplicated_resolution_list
    

    def append_camera_current_config(self, config):
        config['is_camera_available'] = self.is_camera_detected()
        if self.is_camera_detected():
            config['available_camera_resolutions'] = self.resolutions_wh
            print( self.resolutions_wh )
            config['current_camera_resolution'] = self.current_resolution['resolution']
        return config
    
    # When user config options change, or the resolution changes then change the position of the timestamp text on screen
    @staticmethod
    def recalculate_timestamp_text_position( timestamp_scale_name, cam_width, cam_height, image_rotation_degrees, timestamp_position ):
        timestamp_text = str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


        timestamp_scale_factor = CameraHandler.scale_name_to_scale_value(timestamp_scale_name)
        timestamp_text_scale = 0.5
        timestamp_text_scale *= (cam_height/ 480)
        timestamp_text_scale *= timestamp_scale_factor

        timestamp_thickness_inner = int((cam_height/ 480))
        if timestamp_thickness_inner < 1:
            timestamp_thickness_inner = 1
        timestamp_thickness_outer = timestamp_thickness_inner * 2

        (text_width, text_height), baseline = cv2.getTextSize(
            timestamp_text, cv2.FONT_HERSHEY_SIMPLEX,
            timestamp_text_scale, timestamp_thickness_outer
        )

        top_padding_pixels_at_480 = 1
        side_padding_pixels_at_640 = 1
        top_padding_resolution_scaled = int(((cam_height/ 480) * top_padding_pixels_at_480))
        side_padding_pixels_resolution_scaled = int(((cam_width/ 640) * side_padding_pixels_at_640))

        image_width = cam_width
        image_height = cam_height
        if image_rotation_degrees == 90 or image_rotation_degrees == 270:
            image_width = cam_height
            image_height = cam_width

        if timestamp_position == 'top-left':
            timestamp_left_edge = side_padding_pixels_resolution_scaled
            timestamp_bottom_edge = text_height + top_padding_resolution_scaled
        elif timestamp_position == 'top-right':
            timestamp_left_edge = image_width - text_width - side_padding_pixels_resolution_scaled
            timestamp_bottom_edge = text_height + top_padding_resolution_scaled
        elif timestamp_position == 'bottom-left':
            timestamp_left_edge = side_padding_pixels_resolution_scaled
            timestamp_bottom_edge = image_height - top_padding_resolution_scaled - 1
        else:
            timestamp_left_edge = image_width - text_width - side_padding_pixels_resolution_scaled
            timestamp_bottom_edge = image_height - top_padding_resolution_scaled - 1

        # Precompute the dilation kernel once here rather than every frame in add_timestamp()
        outline_width = max(1, timestamp_thickness_outer - timestamp_thickness_inner)
        timestamp_outline_kernel = cv2.getStructuringElement(
            cv2.MORPH_ELLIPSE, (outline_width * 2 + 1, outline_width * 2 + 1)
        )
        # Small bounding-box padding for the mask ROI (covers dilation + AA overhang)
        timestamp_mask_pad = outline_width * 3 + 4
        
        return {
            "timestamp_text_scale": timestamp_text_scale,
            "timestamp_left_edge": timestamp_left_edge,
            "timestamp_bottom_edge": timestamp_bottom_edge,
            "timestamp_thickness_inner": timestamp_thickness_inner,
            "timestamp_thickness_outer": timestamp_thickness_outer,
            "timestamp_outline_kernel": timestamp_outline_kernel,
            "timestamp_mask_pad": timestamp_mask_pad
            
        }

    @staticmethod
    def add_timestamp( frame, params ):
        timestamp_text = str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        x0, y0 = params['timestamp_left_edge'], params['timestamp_bottom_edge']
        (text_w, text_h), baseline = cv2.getTextSize(
            timestamp_text, cv2.FONT_HERSHEY_SIMPLEX, params['timestamp_text_scale'], params['timestamp_thickness_outer']
        )
        pad = params['timestamp_mask_pad']
        x_min = max(x0 - pad, 0)
        y_min = max(y0 - text_h - pad, 0)
        x_max = min(x0 + text_w + pad, frame.shape[1])
        y_max = min(y0 + baseline + pad, frame.shape[0])

        roi = frame[y_min:y_max, x_min:x_max]
        local_org = (x0 - x_min, y0 - y_min)

        mask = np.zeros(roi.shape[:2], dtype=np.uint8)
        cv2.putText(mask, timestamp_text, local_org, cv2.FONT_HERSHEY_SIMPLEX,
                    params['timestamp_text_scale'], 255, params['timestamp_thickness_inner'], cv2.LINE_AA)

        outline_mask = cv2.dilate(mask, params['timestamp_outline_kernel'])

        outline_alpha = (outline_mask.astype(np.float32) / 255.0)[..., None]
        roi[:] = (roi * (1 - outline_alpha)).astype(np.uint8)

        fill_alpha = (mask.astype(np.float32) / 255.0)[..., None]
        roi[:] = (roi * (1 - fill_alpha) + 255 * fill_alpha).astype(np.uint8)

        frame[y_min:y_max, x_min:x_max] = roi
        return frame


    # Returns a PNG image with some text on it for debugging
    def create_message_image(text):
        img = np.zeros((150, 640, 3), np.uint8)
        font = cv2.FONT_HERSHEY_SIMPLEX
        textsize = cv2.getTextSize(text, font, 1, 2)[0]
        textX = (img.shape[1] - textsize[0]) // 2
        textY = (img.shape[0] + textsize[1]) // 2
        cv2.putText(img, text, (textX, textY), font, 1, (0, 0, 255), 2, cv2.LINE_AA)
        ret, buffer = cv2.imencode('.png', img)
        return buffer.tobytes()
    
    
    def add_viewing_start_camera( self, username ):
        username = username.lower()
        with self.update_login_lock:
            if username in self.logged_in_users:
                self.logged_in_users[username]+=1
            else:
                self.logged_in_users[username] = 1
            self.pause_camera( False )
           
    def remove_viewing_user_stop_camera( self, username ):
        username = username.lower()
        with self.update_login_lock:
            if username in self.logged_in_users:
                self.logged_in_users[username] -= 1
                if self.logged_in_users[username] < 1:
                    del self.logged_in_users[username]
                    self.config.write_log_line('info', False, username, '', 'disconnect', "Stopped viewing camera.")
                else:
                    self.config.write_log_line('info', False, username, '', 'disconnect', "Session disconnected.")
            # If there are no other users connected - pause the camera
            if sum(self.logged_in_users.values()) < 1:
                self.pause_camera( True )

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
        
        yield (b'--frame\r\n'
                   b'Content-Type: image/png\r\n\r\n' + CameraHandler.create_message_image("Camera starting...") + b'\r\n')
                   
        self.add_viewing_start_camera(username)
        # Estimate a realistic number for the maximum wi-fi transfer capability of the pi
        # in bytes/s. We will try and avoid exceeding this
        max_rate_bytes_s = self.config.get_parameter_value('max_wifi_bandwidth')*1024*1024  
        
        # The minimum time between frames to avoid swamping the wifi
        min_interframe_delay = 1/30 

        try:
            last_posted_frame = -1
            last_frame_post_time = 0
            stats_start_time = time.time()
            frames_sent = 0
            bandwidth_bytes_consumed_session = 0
    
            while self.is_user_viewing(username):
                new_frame = False
                
                # Check if a new frame ID exists
                if self.frame_id.value > 0 and last_posted_frame < self.frame_id.value:
                    if self.frame_gen_lock.acquire(block=False):
                        try:
                            length = self.frame_len.value
                            raw_bytes = self.bg_shared_mem.buf[:length]
                            
                            # Acquire the image
                            # Verify is a valid JPEG (Must start with 0xFFD8 and end with 0xFFD9)
                            if length > 100 and raw_bytes[:2] == b'\xff\xd8' and raw_bytes[-2:] == b'\xff\xd9':
                                frame = bytes(raw_bytes)
                                last_posted_frame = self.frame_id.value  # Only update on valid read
                                new_frame = True
                                total_sessions_open = self.get_total_num_viewing_sessions()
                                if total_sessions_open > 0:
                                    max_fps = (max_rate_bytes_s / total_sessions_open ) / length
                                    min_interframe_delay = 1/max_fps
                        finally:
                            self.frame_gen_lock.release()

                # New frame available to post to client
                if new_frame:

                    payload = (
                        b"--frame\r\n"
                        b"Content-Type: image/jpeg\r\n"
                        b"Content-Length: " + str(len(frame)).encode() + b"\r\n"
                        b"\r\n" + frame + b"\r\n"
                    )

                    yield payload
                    frames_sent+=1
                    bandwidth_bytes_consumed_session += len(frame)     
                    
                    now = time.time()
                    # Limit the frame rate to avoid swamping the wi-fi
                    remaining_frame_delay = 0.01
                    if (now - last_frame_post_time) < min_interframe_delay:
                        remaining_frame_delay = min_interframe_delay - (now - last_frame_post_time)
                    if now - stats_start_time > 1.0:
                        sent_fps = frames_sent / (now - stats_start_time)
                        session_bandwidth_mbs = (bandwidth_bytes_consumed_session / (now - stats_start_time))/(1024**2)
                        print(f"streamed FPS={sent_fps:.2f} session_bandwidth={session_bandwidth_mbs:.2f}MB/s")
                        frames_sent = 0
                        bandwidth_bytes_consumed_session = 0
                        stats_start_time = now                        
                                       
                    time.sleep(remaining_frame_delay)
                    last_frame_post_time = now
                else:
                    time.sleep(0.01)
                   
            yield (b'--frame\r\n'
                   b'Content-Type: image/png\r\n\r\n' + CameraHandler.create_message_image("Logged out") + b'\r\n')
        except GeneratorExit:
            print("Generator yield exit")
            return
        finally:
            self.remove_viewing_user_stop_camera( username )
