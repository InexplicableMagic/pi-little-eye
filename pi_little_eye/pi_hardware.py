from gpiozero import pi_info

class PiHardware:
    def __init__(self ):
        self.pi_info = pi_info()
        self.which_pi_am_i = self.pi_info.model
        self.memory = self.pi_info.memory
        self.wifi_max_bandwdith = PiHardware.__suggest_wifi_bandwidth( self.which_pi_am_i )
    
    def get_pi_model( self ):
        return self.which_pi_am_i
        
    def get_pi_memory( self ):
        return self.memory

    def get_suggested_max_wifi_bandwidth( self ):
        return self.wifi_max_bandwdith

    # Suggest a practical maximum bandwidth
    # figure for each pi model in MBytes/s
    # for tranmission over the integrated wi-fi

    @staticmethod
    def __suggest_wifi_bandwidth( pi_model ):
        match pi_model:
            case 'Zero W':
                return 3
            case 'Zero2W' | '3B':
                return 3
            case '3B+' | '3A+' | 'CM4':
                return 15
            case '4B' | '400':
                return 20
            case '5B' | '5' | '500':
                return 22
            # For an unknown model go down the middle
            case _:
                return 15

pi_hardware = PiHardware()



    
