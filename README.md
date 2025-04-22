<img align="right" width="250px" src="docs/security-camera-with-raspberry.jpg">

**Pi Little Eye** is a security camera for the Raspberry Pi with the official camera modules.<br>

- Viewable on all devices with a browser.
- No mobile app required. All phone types supported.
- No cloud. No subscriptions. No Telemetry.
- Image can be rotated and time stamped
- Video can be streamed to other devices e.g. for storage
- Supports multiple user accounts
- Supports IP whitelists and block lists
- Runs over https
- Maintains access logs

## Installation

These instructions are for Raspberry Pi OS 64-bit bookworm edition upwards. 

The raspberry pi must have an official camera module attached (any version). The project does not work with USB cameras. See here for [raspberry pi camera installation instructions](https://leoncode.co.uk/articles/installing-the-raspberry-pi-camera-module/).

To install Pi Little Eye into a Python virtual env:

```
git clone https://github.com/InexplicableMagic/pi-little-eye/
cd pi-little-eye

python -m venv camera-env --system-site-packages
source camera-env/bin/activate
pip install -r requirements.txt
```

The ```--system-site-packages``` option permits use of Python modules installed system-wide outside of a venv. This is particularly intended for the picamera2 module which should be installed by default in bookworm and does not seem to install particularly easily into a venv.

## Starting the Camera

To start the camera:

```
source camera-env/bin/activate
./camera_server.py
```

This will start the camera on port 5220 by default. You can change the port with the ```--port``` option.

To start the camera software in the background do: ```nohup ./camera_server.py &```

The default host interface is ```0.0.0.0``` which is for access from any IPv4 network interface and should be fine for most purposes. However, if you want to start the camera on the IPv6 interface it can be achieved with this option: ```--host ::```


## Usage

Access the camera via a web browser like this. Note, the camera runs over **https** and is not accessible via http:

```https://your-raspberry-pi:5220/```

When first connecting you will receive a **certificate warning**. This is entirely expected and is because a self-signed certificate is being used. Just click through it by whatever means is provided in your browser. Often the button you need to click to ignore the message is tiny and obscure to avoid people not reading it. On Chrome it's under "Advanced". Once you have clicked through it once, you won't see the message again. If you are unsure what this message means, see the [self-signed certifiate section](#Self-Signed-Certificate) below for an explanation. If you have a valid certificate for your raspberry pi, this can be supplied in PEM format using the ```--cerificate``` and ```--key``` options.

On first connection, you will be asked to set the initial admin username and password for the camera:

<img src="docs/set-admin-password.png" width="200px" >

If you forget the admin password, the camera configuration can be reset with the ```--factory-reset``` command line option.

The next screen will ask you to login and then the camera image should be displayed:

<img width="400px" src="docs/main-window.jpg">

There is a hamburger menu in the upper left corner for options and a logout button top-right.

## Configuration

Clicking the top-left hamburger icon shows the configuration menu. There are four buttons at the top which each displays a different panel of options.

The camera options panel allows modification of the resolution of the camera and image rotation in 90 degree steps. Whether the timestamp is displayed can also be set in addition to the position and font size of the timestamp text.

<img src="docs/camera-options.png" width="400px" >

The users panel allows additional camera users to be added. There are two levels of user account: "viewer" and "admin". A viewer may only view the camera and may not modify options. An admin has access to all configuration options.

An admin user can lock (or unlock) another user's account. An admin can also logout another user. This can be useful if you have forgotten to logout on a device that you no longer have access to. If you wish to logout the current user, use the button on the top right. This will logout all sessions on all computers.

Additionally application keys may be added on this panel (See the [Streaming Video](#Streaming-Video) section below for usage).

<img src="docs/additional-users.png" width="400px" >

By default any IP can access the camera. However a specific set of IPs can be whitelisted using the top box on the security panel. One trailing wildcard (an asterisk character) is also permitted to wildcard a specific IP range. To enable the whitelist click the "Only below IP ranges may access camera" radio button.

Specific IPs or ranges can also be placed on a block list using the lower box. These IPs (or ranges) will be prevented from accessing the camera. Check the "Enable IP block list" checkbox to activate the list.

Blocking IPs is not a very robust method of preventing access to the camera, someone intent on access might use a VPN or such to acquire a different IP. It can however be a useful counter-measure against nuisance bots that are persistently trying passwords. Often in practice the bot will only be present on one or a limited  set of IPs that can be blocked and the bot owner will not bother to move it but just go elsewhere. Another alternate to dealing with this kind of problem is to move the camera to a different port with the ```--port``` command line option.

<img src="docs/ip-ranges.png" width="400px" >

If you accidentally lock yourself out through misconfiguration of IP ranges, use the ```--disable-ip-lists``` command line option which will disable the access lists.

A log of all user activity is recorded in the logs panel including the connecting IP and user name. The logs can be cleared with the button on the right.

<img src="docs/logs.png" width="400px" >


### Streaming Video

To stream the video to another device, first an application key is required to authenticate with the camera. An option to generate application keys can be found in the account settings under the configuration menu:

<img width="400px" src="docs/app-key-and-secret.png">

The secret is only displayed once and cannot be recovered. If you forget the secret, simply generate a new application key.

The video is available in MJPEG format at the endpoint: ```/api/v1/video/mjpeg```. The appkey and associated secret are supplied as GET parameters as follows. This will save the video to the file "output.mp4" in the native MPJEG codec:

```curl -k -s "https://your-raspberry-pi:5220/api/v1/video/mjpeg?appkey=THE-APP-KEY&secret=THE-SECRET" | ffmpeg -i - -vcodec copy output.mp4```

MPJEG video files can be quite large. If you prefer, you can compress the video in real time into e.g. H.264 (one of the most common video codecs) on the fly like this which will produce a smaller file size. The disadvantage is this will consume a fairly large amount of CPU resource to do the compression whereas storing the original MJPEG requires almost no CPU.

```curl -k -s "https://your-raspberry-pi:5220/api/v1/video/mjpeg?appkey=THE-APP-KEY&secret=THE-SECRET" | ffmpeg -i - -vcodec libx264 output-compressed.mp4```

### Self-Signed Certificate

When connecting to the camera for the first time, your brower will display a large fearsome looking message proclaiming that the connection is "not secure" or some such wording. Don't worry, the connection **is encrypted** with TLS (https) to at least the same standard as every other https connection, and possibly better. What the message is saying is that your browser is unable to verify who owns the camera.

<img width="200px" src="docs/chrome-mobile-connection-not-secure.png">

When you connect to your bank over the web, how do you know that your bank actually owns the server you are connecting to? This is achieved by having a "trusted" 3rd party counter-sign that the certificate presented by the bank's server does in fact belong to the bank. In this case we have not done that step because it involves either money or a beaurocratic verification process. Instead the camera auto-generates what's called a "self-signed" certificate which does not bear the counter-signatory from the 3rd party that your browser expects. While you definitely shouldn't click through the message if you are trying to connect to your bank (and that's why it's so loud and bold) in this case it's fine because we already know who owns the camera - you do. In this instance there is no concern about who owns the device.

If you have a browser valid certificate for your camera, you can supply it on the command line and you won't get the message. However, if you're only ever going to be using the camera yourself, there is little point in going to that trouble as it won't do anything to enhance security over a self-signed certificate. All it does is get rid of the warning. Once you've clicked through it once, the browser will remember your decision and you won't be asked again.

