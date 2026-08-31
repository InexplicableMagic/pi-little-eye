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
import logging
import io
import signal
import queue
from multiprocessing import get_context, shared_memory, Pipe
from PIL import Image, ImageDraw
from .db_config_handler import *

class CameraHandler:

    def __init__(self, config, worker ):
        self.config = config
        self.gunicorn_worker = worker
        #Currently supports the first found camera
        self.selected_camera_number = config.get_parameter_value( 'cam_number' )
        self.timestamp_scale_name = self.config.get_parameter_value( 'timestamp_scale_factor' )
        self.timestamp_position = config.get_parameter_value( 'timestamp_position' )
        self.display_timestamp = config.get_parameter_value( 'display_timestamp' )
        self.camera_state_change_lock = threading.Lock()  # Lock pause/resume state on camera
        self.option_change_lock = threading.Lock()  # Lock changes to user config options in this object
        self.update_login_lock = threading.Lock()   # Lock updates to list of logged in users
        self.stream_update_lock = threading.Lock()  # Lock for changing stream_queues
        self.stream_queues = [] # List of queues for sending config updates to running streams
        self.last_frame = None
        self.logged_in_users = dict()
        # Turn off the verbose camera logging
        Picamera2.set_logging(logging.ERROR)
        os.environ["LIBCAMERA_LOG_LEVELS"] = "ERROR"
        #Enquire about the resolutions the attached camera can do
        self.camera_detected = False
        self.all_cam_props = self.__get_camera_properties( )
        self.camera_list = []

        # If there are now fewer cameras than previously - reset the selected camera number to zero
        if self.selected_camera_number > len( self.all_cam_props ):
            self.config.insert_or_update_parameter( 'cam_number', 'int', 0 )
            self.selected_camera_number = 0

        if len( self.all_cam_props ) > 0:
            self.camera_detected = True          
    
        # Start a separate background process for each camera
        for camera_num in range(0,  len(self.all_cam_props) ):
            resolutions = self.all_cam_props[camera_num]['resolutions']
            # Resolutions as a simple list of widths and heights
            if resolutions != None and len(resolutions) > 0:
                camera_details = self.start_camera( camera_num )
                self.camera_list.append( camera_details )
 
        # Thread watches that the background process is running
        self.background_watcher_running = True
        self.bg_process_watcher_thread = threading.Thread(target=self.bg_process_watcher, daemon=True)
        self.bg_process_watcher_thread.start()


    def start_camera( self, camera_num ):
        with self.camera_state_change_lock:
            camera_details = {  }
            resolutions = self.all_cam_props[camera_num]['resolutions']

            user_res_width = self.config.get_parameter_value( f"{camera_num}:cam_res_width" )
            user_res_height = self.config.get_parameter_value( f"{camera_num}:cam_res_height" )
            image_rotation_degrees = self.config.get_parameter_value( f"{camera_num}:image_rotation" )
            if user_res_width is None or user_res_height is None or image_rotation_degrees is None:
                # Camera has not previously been initialised in config - set defaults
                user_res_width = 640
                user_res_height = 480
                image_rotation_degrees = 0

            camera_details['paused'] = True
            camera_details['resolutions_wh'] = CameraHandler.resolutions_to_width_height_list( resolutions )
            camera_details['available_resolutions'] = resolutions
            camera_details['current_resolution'] = CameraHandler.__suggest_camera_resolution( resolutions, ( user_res_width, user_res_height ) )
            
            self.config.insert_or_update_parameter( f"{camera_num}:cam_res_width", 'int', camera_details['current_resolution']['resolution'][0] )
            self.config.insert_or_update_parameter( f"{camera_num}:cam_res_height", 'int', camera_details['current_resolution']['resolution'][1] )

            camera_details['current_rotation'] = image_rotation_degrees
            self.config.insert_or_update_parameter( f"{camera_num}:image_rotation", 'int', camera_details['current_rotation'] )
                       
            ctx = get_context("spawn")  # explicit spawn: fresh interpreter, no inherited state

            camera_details['bg_shared_mem'] = shared_memory.SharedMemory(create=True, size=4*1024*1024)
            camera_details['frame_len'] = ctx.Value("i", 0)   # Length in bytes of the current frame
            camera_details['frame_id'] = ctx.Value("i", -1)    # Incremented every time a new frame is published
            camera_details['frame_gen_lock'] = ctx.Lock()
            camera_details['camera_control_pipe'], child_cam_control_pipe = ctx.Pipe()  # For sending configuration changes to the camera processs
            child_msg_pipe, camera_details['message_pipe'] = ctx.Pipe()  # For sending configuration changes to the camera processs
                            
            camera_initial_params = self.generate_camera_parameter_message(camera_num, camera_details=camera_details)
            camera_details['camera_process'] = ctx.Process(
                target=CameraHandler.bg_image_producer,
                args=(  camera_num,
                        child_msg_pipe,
                        camera_details['bg_shared_mem'].name, 
                        camera_details['frame_gen_lock'], 
                        camera_details['frame_len'], 
                        camera_details['frame_id'], 
                        child_cam_control_pipe,
                        camera_initial_params ),
                daemon=False
            )
            
            camera_details['camera_process'].start()
            camera_details['available'] = True

            return camera_details

        
    def generate_camera_parameter_message( self, camera_number, camera_details = None ):
        if camera_details is None:
            camera_details = self.camera_list[camera_number]

        with self.option_change_lock:
            cam_param_block = {
                'selected_resolution': camera_details['current_resolution'],
                'available_resolutions' : camera_details['available_resolutions'],
                'selected_camera_number': camera_number,
                'timestamp_position': self.timestamp_position,
                'timestamp_scale_name': self.timestamp_scale_name,
                'display_timestamp': self.display_timestamp,
                'rotation': camera_details['current_rotation'],
                'jpeg_quality': 70
            }
            
            return cam_param_block

    def send_camera_message( self, camera_num, message ):
        if camera_num >= 0 and camera_num < len( self.camera_list ):
            if self.camera_list[camera_num]['available']:
                if self.camera_list[camera_num]['camera_process'].is_alive():    
                    try:
                        self.camera_list[camera_num]['camera_control_pipe'].send( message )
                        return True
                    except Exception:
                        pass
        return False     

        
    def pause_camera( self, new_state, camera_num ):
        if camera_num >=0 and camera_num < len(self.camera_list):
            with self.camera_state_change_lock:
                if new_state != self.camera_list[camera_num]['paused']:
                    self.camera_list[camera_num]['paused'] = new_state
                    msg = { 'paused': new_state }
                    self.send_camera_message( camera_num, msg )
   

    def close_down_camera_process( self, cam ):
        with self.camera_state_change_lock:
            self.camera_list[cam]['available'] = False
            self.send_camera_message( cam, { 'stop': True } )

        self.camera_list[cam]['camera_process'].join( timeout=5 )

        if self.camera_list[cam]['camera_process'].is_alive():
            self.camera_list[cam]['camera_process'].terminate()
            self.camera_list[cam]['camera_process'].join( timeout=1 )  # Reclaim PID from process table
            
        # Close down shared memory used to transmit frames from the camera
        # Memory leak if not closed down
        try:
            self.camera_list[cam]['bg_shared_mem'].close()
        except Exception as e:
            pass

        try:
            self.camera_list[cam]['bg_shared_mem'].unlink()
        except Exception as e:
            pass

        try:
           self.camera_list[cam]['camera_control_pipe'].close()
           self.camera_list[cam]['message_pipe'].close()
        except Exception:
            pass
        
             
    # Close down and tidy up background process(es) that generates camera frames
    # One process per camera
    def close_down( self ):

        # Close down the watcher that tries to keep the camera background process running
        self.background_watcher_running = False

        # Tell all streams relying on the cameras to stop
        for cam in range(0, len(self.camera_list)):
            self.close_down_camera_process( cam )
            
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
    
    # Determines if the camera needs to be restarted in order to
    # effect the paramater change
    @staticmethod
    def camera_restart_needed( existing_params, new_params ):
        # If the camera was never initialised, a restart is required
        if existing_params is None:
            return True

        # If the rotation changed to or from a rotation handled in hardware
        # this requires a restart
        if new_params['rotation'] != existing_params['rotation']:
            if new_params['rotation'] == 180 or new_params['rotation'] == 0:
                return True
            if existing_params['rotation'] == 180 or existing_params['rotation'] == 0:
                return True

        # If the resolution changed a restart is required
        if new_params['selected_resolution']['resolution'][0] != existing_params['selected_resolution']['resolution'][0]:
            return True
        if new_params['selected_resolution']['resolution'][1] != existing_params['selected_resolution']['resolution'][1]:
            return True

        return False
    
    # Background process that obtains the camera image
    # Initially starts in the paused state and then needs waking up to generate images
    @staticmethod
    def bg_image_producer(cam_num, msg_pipe, shm_name: str, lock, frame_len, frame_id, control_pipe, params):
        running = True

        shm = shared_memory.SharedMemory(name=shm_name)
        # Max FPS to ever use
        max_fps=30
        # Actual camera maximum FPS setting as some resolutions can't handle max_fps
        camera_fps = max_fps
        fid = 0
        parameter_change = True
        camera_restart_required = True
        picam2 = None
        paused = True

        # Used for checking if picamera2 module has hung
        signal.signal(signal.SIGALRM, CameraHandler.raise_timeout)
        
        try:
            while running:
                start_time = time.time()
                
                # Check for messages about state or config changes
                # Use a while loop to drain pending messages to get
                # to the latest state
                while control_pipe.poll(0):
                    msg = control_pipe.recv()
                    if msg is not None:
                        # Check for state change messages
                        if 'paused' in msg:
                            paused = msg['paused']
                        elif 'stop' in msg:
                            if msg['stop']:
                                running = False
                                break
                        else:
                            # This is a config change message
                            camera_restart_required = CameraHandler.camera_restart_needed( params, msg )
                            params = msg
                            parameter_change = True
                    
                if parameter_change or picam2 is None:
                    # Assumed parameters are validated by this point

                    timestamp_params = CameraHandler.recalculate_timestamp_text_position( params['timestamp_scale_name'], params['selected_resolution']['resolution'][0] ,params['selected_resolution']['resolution'][1] , params['rotation'], params['timestamp_position'] )
                    parameter_change = False
                    
                    #Changing resolution requires a camera restart
                    if camera_restart_required == True or picam2 is None:
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
                            camera_restart_required = False
                        except Exception as e:
                            # On error - try resetting the camera resolution to the minimum
                            # User may have selected too high a resolution
                            CameraHandler.camera_reset_close(picam2)
                            picam2 = None
                            params['selected_resolution'] = params['available_resolutions'][0]

                
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

                            
                            # Notify the main process of the resolution change
                            err_type="exception"
                            if isinstance(e, TimeoutError):
                                err_type="timeout"
                            msg_pipe.send( { "camera_num": cam_num, "error": err_type, "message": str(e), 
                                             "action": "resolution_reset", "resolution": params['selected_resolution'] } )                            
                    
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
            msg_pipe.close()
            control_pipe.close()

    # Thread to check the camera management process is running
    # Restarts the process if it failed
    # Also listens for messages about recoverable internal failures within the process
    def bg_process_watcher( self ):
        was_msg = False
        # Don't check if the background process has failed for the first 30 seconds to give it time to start in the first place
        next_bg_process_check_time = time.time() + 30
        while self.background_watcher_running:
            for camera in self.camera_list:
                if camera['available']:
                    if camera['message_pipe'].poll(0):
                        try:
                            msg = camera['message_pipe'].recv()
                            if msg is not None:
                                was_msg = True
                                if isinstance( msg, dict ):
                                    if 'error' in msg:
                                        # The camera reset it's resolution (due to an error) so reset the config parameters to reflect this change
                                        if 'action' in msg and msg['action'] == 'resolution_reset':
                                            if 'resolution' in msg and isinstance( msg['resolution'], dict ) and 'camera_num' in msg:
                                                self.config.write_log_line('error', False, None, '', 'camera', f"Camera failed. Reset resolution and restarted.")
                                                self.__change_resolution(msg['resolution'], msg['camera_num'])

                        except Exception as e:
                            pass

            # Restart any failed camera background processes
            if self.background_watcher_running:
                if time.time() > next_bg_process_check_time:
                    for cam_num in range( 0, len( self.camera_list) ):
                        if not camera['camera_process'].is_alive():
                            if self.background_watcher_running:
                                self.config.write_log_line('error', False, None, '', 'camera', f"Camera background process unexpectedly stopped. Attempting restart.")
                                self.close_down_camera_process( cam_num )
                                self.camera_list[cam_num] = self.start_camera( cam_num )
                    
                    # Check for failures every 10 seconds
                    next_bg_process_check_time = time.time()+10

            # If there was a message, immediately test again for another message
            # Need to consume the queue quickly to avoid the background process blocking due to pipe filling
            if not was_msg:
                time.sleep(0.2)
            was_msg = False            

    def __set_new_rotation( self, rotation, camera_number ):
        with self.option_change_lock:
            if camera_number >= 0 and camera_number < len(self.camera_list):
                if rotation != None and isinstance(rotation, int) and rotation != self.camera_list[ camera_number ]['current_rotation']:
                    if (rotation <= 270) and ((rotation % 90) == 0):
                        self.camera_list[ camera_number ]['current_rotation'] = rotation
                        self.config.insert_or_update_parameter( f"{camera_number}:image_rotation", 'int', rotation )    

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

    def post_camera_options_change( self, camera_number ):
        if camera_number >= 0 and camera_number < len( self.camera_list ):
            msg = self.generate_camera_parameter_message(camera_number)
            self.send_camera_message( camera_number, msg )

    # Change the camera resolution - can be set whilst the camera is running
    def __change_resolution(self, new_resolution, camera_number):
        with self.option_change_lock:
            if camera_number >= 0 and camera_number < len( self.camera_list ):
                #Validate the user input
                if new_resolution is not None and isinstance(new_resolution, dict) and 'resolution' in new_resolution:
                    hw_res = new_resolution['resolution']
                    if hw_res is not None and isinstance(hw_res, (list, tuple)):
                        if len( hw_res ) == 2 and isinstance( hw_res[0], int) and isinstance( hw_res[1], int):
                            if hw_res[0] > 128 and hw_res[1] > 128:
                                #Don't change resolution if it's the same as the current resolutions
                                #Validates the resolution passed in is a mode available on this camera
                                if self.camera_detected:
                                    new_resolution = CameraHandler.__suggest_camera_resolution( self.camera_list[camera_number]['available_resolutions'], hw_res )
                                    if (new_resolution['resolution'][0] != self.camera_list[camera_number]['current_resolution']['resolution'][0]) or \
                                       (new_resolution['resolution'][1] != self.camera_list[camera_number]['current_resolution']['resolution'][1]):
                                        # Update the config with the selected resolution
                                        self.camera_list[camera_number]['current_resolution'] = new_resolution
                                        self.config.insert_or_update_parameter( f"{camera_number}:cam_res_width", 'int', new_resolution['resolution'][0] )
                                        self.config.insert_or_update_parameter( f"{camera_number}:cam_res_height", 'int', new_resolution['resolution'][1] )                            

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
    # Must already be validated
    def change_camera_config( self, post_data ):
        if post_data is not None and isinstance( post_data, dict):
            # Common parameters
            if 'timestamp_scale' in post_data:
                self.__set_new_timestamp_scale( post_data[ 'timestamp_scale' ] )
            if 'timestamp_position' in post_data:
                self.__set_new_timestamp_position( post_data[ 'timestamp_position' ] )
            if 'display_timestamp' in post_data:
                self.__set_display_timestamp( post_data[ 'display_timestamp' ] )
            if 'max_wifi_bandwidth' in post_data:
                self.publish_stream_config_update( { 'max_wifi_bandwidth': post_data['max_wifi_bandwidth'] } )
            
            # Per camera settings
            if 'cameras' in post_data:
                if post_data['cameras'] is not None and isinstance( post_data['cameras'], (list, tuple) ):
                    for camera in post_data['cameras']:
                        if 'camera_number' in camera:
                            if isinstance( camera['camera_number'], int ) and camera['camera_number'] >= 0 and camera['camera_number'] < len(self.camera_list):
                                cam_num = camera['camera_number']
                                if 'image_rotation' in camera:
                                    self.__set_new_rotation( camera[ 'image_rotation' ], cam_num )
                                if 'selected_resolution' in camera:
                                    self.__change_resolution( camera[ 'selected_resolution' ], cam_num )

            for i in range( 0, len( self.camera_list ) ):
                self.post_camera_options_change( i )
            
    
    # Get the resolutions the camera can do  
    # Called once on boot and must be called before background thread starts
    def __get_camera_properties( self ):
        camera_properties = []

        # The pi 5 can have two cameras
        for camera_number in range(0,1):
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
                properties = { 'resolutions': resolutions, 'aspect_ratio': aspect_ratio_str }
                camera_properties.append( properties )
            except:
                # No camera present on this port
                pass
        
        return camera_properties

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
        config['camera']['is_camera_available'] = self.is_camera_detected()
        camera_section = [  ]
        if self.is_camera_detected():
            for i in range(0, len(self.camera_list)):
                this_cam = {  }
                this_cam['camera_number'] = i
                this_cam['available_resolutions'] = self.camera_list[i]['available_resolutions']
                this_cam['current_resolution'] = self.camera_list[i]['current_resolution']
                this_cam['image_rotation'] = self.camera_list[i]['current_rotation']
                
                camera_section.append( this_cam )
            
        config['camera']['cameras'] = camera_section        
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
        
        h, w = frame.shape[:2]
        x_min, y_min = max(x0 - pad, 0), max(y0 - text_h - pad, 0)
        x_max, y_max = min(x0 + text_w + pad, w), min(y0 + baseline + pad, h)

        roi = frame[y_min:y_max, x_min:x_max]
        local_org = (x0 - x_min, y0 - y_min)

        mask = np.zeros(roi.shape[:2], dtype=np.uint8)
        cv2.putText(mask, timestamp_text, local_org, cv2.FONT_HERSHEY_SIMPLEX,
                    params['timestamp_text_scale'], 255, params['timestamp_thickness_inner'], cv2.LINE_AA)

        outline_mask = cv2.dilate(mask, params['timestamp_outline_kernel'])

        is_color = len(frame.shape) == 3
        if is_color:
            inv_outline = cv2.cvtColor(cv2.bitwise_not(outline_mask), cv2.COLOR_GRAY2BGR)
            mask_c = cv2.cvtColor(mask, cv2.COLOR_GRAY2BGR)
        else:
            inv_outline = cv2.bitwise_not(outline_mask)
            mask_c = mask

        roi_blackened = cv2.multiply(roi, inv_outline, scale=1.0/255.0)
        
        roi_final = cv2.add(roi_blackened, mask_c)

        frame[y_min:y_max, x_min:x_max] = roi_final
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
    
    # Log that a user is viewing the camera and start it (if not already started)
    def add_viewing_start_camera( self, username, camera_num ):
        username = username.lower()
        with self.update_login_lock:
            if username in self.logged_in_users:
                self.logged_in_users[username][camera_num] += 1
            else:
                self.logged_in_users[username] = [0] * len( self.camera_list )
                self.logged_in_users[username][camera_num] = 1

            self.pause_camera( False, camera_num )
      
    # Register a user as logged out from one specific camera
    # Stop the camera if there are no viewers of that specific camera     
    def remove_viewing_user_stop_camera( self, username, camera_num ):
        username = username.lower()
        with self.update_login_lock:
            if username in self.logged_in_users:
                self.logged_in_users[username][camera_num] -= 1
                total_logins_all_cameras = sum(self.logged_in_users[username])
                if total_logins_all_cameras < 1:
                    self.config.write_log_line('info', False, username, '', 'disconnect', f"Stopped viewing.")
                    del self.logged_in_users[username]
                else:
                    self.config.write_log_line('info', False, username, '', 'disconnect', f"Stopped 1 video stream with {total_logins_all_cameras} streams(s) remaining.")

            # If there are no other users connected to this camera - pause the camera
            total_users_this_camera_only = sum(val[camera_num] for val in self.logged_in_users.values())
            if total_users_this_camera_only < 1:
                self.pause_camera( True, camera_num )

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
               
    def get_total_num_viewing_sessions_all_cameras( self ):
        with self.update_login_lock:
            return sum(map(sum, self.logged_in_users.values()))

    def subscribe_stream_config_updates( self ):
        my_queue = queue.Queue()
        with self.stream_update_lock:
            self.stream_queues.append( my_queue ) 
        return my_queue

    def unsubscribe_stream_config_updates( self, my_queue ):
        with self.stream_update_lock:
            self.stream_queues.remove( my_queue )

    def publish_stream_config_update( self, message ):
        with self.stream_update_lock:
            subs = list( self.stream_queues )
        for q in subs:
            q.put( message )
       
    def stream_camera_video(self, username, camera_num):            
        username = username.lower()

        if camera_num < 0 or camera_num >= len(self.camera_list):
            return

        frame_id = self.camera_list[camera_num]['frame_id']
        frame_len = self.camera_list[camera_num]['frame_len']
        frame_gen_lock = self.camera_list[camera_num]['frame_gen_lock']
        bg_shared_mem = self.camera_list[camera_num]['bg_shared_mem']

        config_updates_q = self.subscribe_stream_config_updates( )
                
        yield (b'--frame\r\n'
                   b'Content-Type: image/png\r\n\r\n' + CameraHandler.create_message_image("Camera starting...") + b'\r\n')
                   
        self.add_viewing_start_camera(username, camera_num)
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
    
            while self.is_user_viewing(username) and self.gunicorn_worker.alive and self.camera_list[camera_num]['available']:
                new_frame = False
                try:
                    msg = config_updates_q.get(block=False)
                    if 'max_wifi_bandwidth' in msg:
                        max_rate_bytes_s = msg['max_wifi_bandwidth'] * 1024 * 1024
                except queue.Empty:
                    pass
                
                # Check if a new frame ID exists
                if frame_id.value > 0 and last_posted_frame < frame_id.value:
                    if frame_gen_lock.acquire(block=False):
                        try:
                            length = frame_len.value
                            raw_bytes = bg_shared_mem.buf[:length]
                            
                            # Acquire the image
                            # Verify is a valid JPEG (Must start with 0xFFD8 and end with 0xFFD9)
                            if length > 100 and raw_bytes[:2] == b'\xff\xd8' and raw_bytes[-2:] == b'\xff\xd9':
                                frame = bytes(raw_bytes)
                                last_posted_frame = frame_id.value  # Only update on valid read
                                new_frame = True
                                # Convert max allowed bandwidth into a framerate split between all viewing users
                                total_sessions_open = self.get_total_num_viewing_sessions_all_cameras( )
                                if total_sessions_open > 0:
                                    max_fps = (max_rate_bytes_s / total_sessions_open ) / length
                                    min_interframe_delay = 1/max_fps
                        finally:
                            frame_gen_lock.release()

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
                    last_frame_post_time = time.time()
                else:
                    time.sleep(0.01)
                   
            yield (b'--frame\r\n'
                   b'Content-Type: image/png\r\n\r\n' + CameraHandler.create_message_image("Logged out") + b'\r\n')
        except GeneratorExit:
            print("Generator yield exit")
            return
        finally:
            self.unsubscribe_stream_config_updates( config_updates_q )
            self.remove_viewing_user_stop_camera( username, camera_num )

