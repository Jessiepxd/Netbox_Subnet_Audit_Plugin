@ECHO OFF
REM PNG Images were generated using ImageMagick "convert" utility.
REM Generate python include file with embedded images using PyEmbeddedImage.
ECHO from wx.lib.embeddedimage import PyEmbeddedImage > images.py
REM Embed all application images
img2py -c -i -a broom.png                 images.py
img2py -c -i -a DeviceLab128.png          images.py
img2py -c -i -a DeviceLab16.png           images.py
img2py -c -i -a DeviceLab32.png           images.py
img2py -c -i -a DeviceLab64.png           images.py
img2py -c -i -a error.png                 images.py
img2py -c -i -a EvertzGold256.png         images.py
img2py -c -i -a Evertz_b.png              images.py
img2py -c -i -a Evertz_g.png              images.py
img2py -c -i -a evertz.png                images.py
img2py -c -i -a gear_b.png                images.py
img2py -c -i -a gear_g.png                images.py
img2py -c -i -a gear.png                  images.py
img2py -c -i -a info.png                  images.py
img2py -c -i -a LAN_16.png                images.py
img2py -c -i -a Linux_b.png               images.py
img2py -c -i -a Linux_g.png               images.py
img2py -c -i -a linux.png                 images.py
img2py -c -i -a ok_green.png              images.py
img2py -c -i -a ok_yellow.png             images.py
img2py -c -i -a PC_b.png                  images.py
img2py -c -i -a PC_g.png                  images.py
img2py -c -i -a pc.png                    images.py
img2py -c -i -a progress0.png             images.py
img2py -c -i -a progress1.png             images.py
img2py -c -i -a progress2.png             images.py
img2py -c -i -a progress3.png             images.py
img2py -c -i -a progress4.png             images.py
img2py -c -i -a progress5.png             images.py
img2py -c -i -a progress6.png             images.py
img2py -c -i -a progress7.png             images.py
img2py -c -i -a progress8.png             images.py
img2py -c -i -a router_b.png              images.py
img2py -c -i -a router_g.png              images.py
img2py -c -i -a spin0.png                 images.py
img2py -c -i -a spin1.png                 images.py
img2py -c -i -a spin2.png                 images.py
img2py -c -i -a spin3.png                 images.py
img2py -c -i -a spin4.png                 images.py
img2py -c -i -a spin5.png                 images.py
img2py -c -i -a spin6.png                 images.py
img2py -c -i -a spin7.png                 images.py
img2py -c -i -a unknown_b.png             images.py
img2py -c -i -a unknown_g.png             images.py
img2py -c -i -a unknown.png               images.py
img2py -c -i -a wait0.png                 images.py
img2py -c -i -a wait1.png                 images.py
img2py -c -i -a wait2.png                 images.py
img2py -c -i -a wait3.png                 images.py
img2py -c -i -a wait4.png                 images.py
img2py -c -i -a wait5.png                 images.py
img2py -c -i -a wait6.png                 images.py
img2py -c -i -a wait7.png                 images.py
img2py -c -i -a warning.png               images.py
img2py -c -i -a web_b.png                 images.py
img2py -c -i -a web_g.png                 images.py
img2py -c -i -a web.png                   images.py
pause