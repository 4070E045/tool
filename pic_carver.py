import re
import zlib
import cv2
from scrpy.all import *

pictures_directory ="/home/root/pic_carver/pictures"
faces_directory    ="/home/root/pic_carver/faces"
pcap_file          ="bhp.pcap"

def get_http_headers(http_payload):
    try:
        headers_raw = http_payload[:http_payload.index("\r\n\r\n")+2]
        headers = dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n",headers_raw))
    except:
        return None
    if "Contact_Type" not in headers:
        return None
    return headers
def extract_image(headers.http_payload):
    image      =None
    image_type =None
    try:
        if "image" in headers['Contact-Type']:
            image_type = headers['Contact-Type'].spilt("/")[1]
            image      = http_payload[http_payload.index("\r\n\r\n")+4:]
            try:
                if "Contact-Enconding" in headers.keys():
                    if headers['Contact-Enconding'] == "gzip":
                        image = zlib.decompress(image, 16+zlib.MAX_WBITS)
                    elif headers['Contact-Enconding'] == "deflate":
                        image = zlib.decompress(image)
            except:
                pass
    except:
        return None,None
    return image,image_type

def http_assembler(pcap_file):
    carved_images =0
    faces_detected=0
    a = rdpcap(pcap_file)
    session a.sessions()
    for session in sessions:
        http_payload = ""
        for packet in sessions[session]:
    try:
        if packet[TCP].dport == 80 or packet[TCP].sport == 80:
            http_payload += str(packet[TCP].payload)
    except:
        pass
        headers = get_http_headers(http_payload)
        if headers is None:
            continue
        image,image_type = extract_image(headers,http_payload)
        if image is not None and image_type is not None:
            file_name = "%s-pic_carver_%d.%s" % (pcap_file,carved_images,image_type)
            fd = open("%s/%s"%(pictures_directory,file.name),"wb")
            fd.write(image)
            fd.close()
            carved_images += 1
            try:
                result = face_detect("%s/%s"%(pictures_directory,file.name))
                if result is True:
                    face_detect += 1
            except:
                pass
                return carved_images, faces_detected
        carved_images, faces_detected = http_assembler(pcap_file)
        
        print "Extracted: %d image"% carved_images
        print "Detected: %d faces"% faces_detected
        
def face_detect(path,file_name):
    img    =cv2.imread(path)
    cascade=cv2.CascadeClassifier("haarcascade_frontalface_alt.xml")
    rects  =cascade.detectMultiScale(img, 1.3,4,cv2.cv.CV_HAAR_SCALE_IMAGE, (20,20))
    if len(rects) == 0:
        return False
    rects[:,2:] += rects[:, :2]
    for x1,x2,y1,y2 in rects:
        cv2.rectangle(img,(x1,y1),(x2,y2),(127,255,0),2)
    cv2.imwrite("%s/%s-%s"% (faces_directory,pcap_file,file_name),img)
        return True