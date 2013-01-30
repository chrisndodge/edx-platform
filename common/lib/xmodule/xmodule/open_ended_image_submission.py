"""
This contains functions and classes used to evaluate if images are acceptable (do not show improper content, etc), and
to send them to S3.
"""

from PIL import Image
import urlparse
import requests
from boto.s3.connection import S3Connection
from boto.s3.key import Key
from django.conf import settings
import pickle
import logging

log = logging.getLogger(__name__)

#Domains where any image linked to can be trusted to have acceptable content.
TRUSTED_IMAGE_DOMAINS = [
    'wikipedia.com',
    'wikipedia.net',
    'wikipedia.org',
    'edxuploads.s3.amazonaws.com'
]

#Suffixes that are allowed in image urls
ALLOWABLE_IMAGE_SUFFIXES = [
    'jpg',
    'png',
    'gif'
]

#Maximum allowed dimensions (x and y) for an uploaded image
MAX_ALLOWED_IMAGE_DIM = 1500

#Dimensions to which image is resized before it is evaluated for color count, etc
MAX_IMAGE_DIM = 150

#Maximum number of colors that should be counted in ImageProperties
MAX_COLORS_TO_COUNT = 16

#Maximum number of colors allowed in an uploaded image
MAX_COLORS = 20

class ImageProperties(object):
    """
    Class to check properties of an image and to validate if they are allowed.
    """
    def __init__(self, image):
        """
        Initializes class variables
        @param image: Image object (from PIL)
        @return: None
        """
        self.image = image
        image_size = self.image.size
        self.image_too_large = False
        if image_size[0] > MAX_ALLOWED_IMAGE_DIM or image_size[1] > MAX_ALLOWED_IMAGE_DIM:
            self.image_too_large = True
        if image_size[0] > MAX_IMAGE_DIM or image_size[1] > MAX_IMAGE_DIM:
            self.image = self.image.resize((MAX_IMAGE_DIM, MAX_IMAGE_DIM))
            self.image_size = self.image.size

    def count_colors(self):
        """
        Counts the number of colors in an image, and matches them to the max allowed
        @return: boolean true if color count is acceptable, false otherwise
        """
        colors = self.image.getcolors(MAX_COLORS_TO_COUNT)
        if colors is None:
            colors = MAX_COLORS_TO_COUNT
        else:
            colors = len(colors)

        too_many_colors = (colors <= MAX_COLORS)
        log.debug("Too many colors: {0}".format(too_many_colors))
        return too_many_colors

    def get_skin_ratio(self):
        """
        Gets the ratio of skin tone colors in an image
        @return: True if the ratio is low enough to be acceptable, false otherwise
        """
        im = self.image
        skin = sum([count for count, rgb in im.getcolors(im.size[0] * im.size[1]) if
                    rgb[0] > 60 and rgb[1] < (rgb[0] * 0.85) and rgb[2] < (rgb[0] * 0.7) and rgb[1] > (rgb[0] * 0.4) and
                    rgb[2] > (rgb[0] * 0.2)])
        bad_color_val = float(skin) / float(im.size[0] * im.size[1])
        if bad_color_val > .4:
            is_okay = False
        else:
            is_okay = True
        log.debug("Skin ratio okay: {0}".format(is_okay))
        return is_okay

    def run_tests(self):
        """
        Does all available checks on an image to ensure that it is okay (size, skin ratio, colors)
        @return: Boolean indicating whether or not image passes all checks
        """
        #image_is_okay = self.count_colors() and self.get_skin_ratio() and not self.image_too_large
        image_is_okay = self.count_colors() and not self.image_too_large
        log.debug("Image too large: {0}".format(self.image_too_large))
        log.debug("Image Okay: {0}".format(image_is_okay))
        return image_is_okay


class URLProperties(object):
    """
    Checks to see if a URL points to acceptable content.  Added to check if students are submitting reasonable
    links to the peer grading image functionality of the external grading service.
    """
    def __init__(self, url_string):
        self.url_string = url_string

    def check_if_parses(self):
        """
        Check to see if a URL parses properly
        @return: success (True if parses, false if not)
        """
        success = False
        try:
            self.parsed_url = urlparse.urlparse(url_string)
            success = True
        except:
            pass

        return success

    def check_suffix(self):
        """
        Checks the suffix of a url to make sure that it is allowed
        @return: True if suffix is okay, false if not
        """
        good_suffix = False
        for suffix in ALLOWABLE_IMAGE_SUFFIXES:
            if self.url_string.endswith(suffix):
                good_suffix = True
                break
        return good_suffix

    def run_tests(self):
        """
        Runs all available url tests
        @return: True if URL passes tests, false if not.
        """
        url_is_okay = self.check_suffix() and self.check_if_parses()
        return url_is_okay


def run_url_tests(url_string):
    """
    Creates a URLProperties object and runs all tests
    @param url_string: A URL in string format
    @return: Boolean indicating whether or not URL has passed all tests
    """
    url_properties = URLProperties(url_string)
    return url_properties.run_tests()


def run_image_tests(image):
    """
    Runs all available image tests
    @param image: PIL Image object
    @return: Boolean indicating whether or not all tests have been passed
    """
    image_properties = ImageProperties(image)
    return image_properties.run_tests()


def upload_to_s3(file_to_upload, keyname):
    '''
    Upload file to S3 using provided keyname.

    Returns:
        public_url: URL to access uploaded file
    '''
    #im = Image.open(file_to_upload)
    #out_im = cStringIO.StringIO()
    #im.save(out_im, 'PNG')

    try:
        conn = S3Connection(settings.AWS_ACCESS_KEY_ID, settings.AWS_SECRET_ACCESS_KEY)
        bucketname = str(settings.AWS_STORAGE_BUCKET_NAME)
        bucket = conn.create_bucket(bucketname.lower())

        k = Key(bucket)
        k.key = keyname
        k.set_metadata('filename', file_to_upload.name)
        k.set_contents_from_file(file_to_upload)
        #k.set_contents_from_string(out_im.getvalue())
        #k.set_metadata("Content-Type", 'images/png')

        k.set_acl("public-read")
        public_url = k.generate_url(60 * 60 * 24 * 365) # URL timeout in seconds.

        return True, public_url
    except:
        return False, "Could not connect to S3."


def get_from_s3(s3_public_url):
    """
    Gets an image from a given S3 url
    @param s3_public_url: The URL where an image is located
    @return: The image data
    """
    r = requests.get(s3_public_url, timeout=2)
    data = r.text
    return data



